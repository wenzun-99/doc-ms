import logging
from io import BytesIO

import magic
from allauth.mfa.adapter import get_adapter as get_mfa_adapter
from allauth.mfa.models import Authenticator
from allauth.mfa.totp.internal.auth import TOTP
from allauth.socialaccount.models import SocialAccount
from allauth.socialaccount.models import SocialApp
from django.contrib.auth.models import Group
from django.contrib.auth.models import Permission
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from PIL import Image
from PIL import ImageOps
from PIL import UnidentifiedImageError
from rest_framework import serializers
from rest_framework.authtoken.serializers import AuthTokenSerializer

from paperless.models import ApplicationConfiguration
from paperless.validators import reject_dangerous_svg
from paperless_mail.serialisers import ObfuscatedPasswordField

logger = logging.getLogger("paperless.settings")


def strip_image_metadata(uploaded_file, mime_type: str | None):
    """Return a copy of ``uploaded_file`` with EXIF/ICC metadata removed."""

    if uploaded_file is None:
        return uploaded_file

    original_position = uploaded_file.tell() if hasattr(uploaded_file, "tell") else None
    image = None

    sanitized = None

    try:
        if hasattr(uploaded_file, "seek"):
            uploaded_file.seek(0)
        image = Image.open(uploaded_file)
        image.load()
    except (UnidentifiedImageError, OSError):
        if hasattr(uploaded_file, "seek") and original_position is not None:
            uploaded_file.seek(original_position)
        return uploaded_file

    try:
        image_format = (image.format or "").upper()
        image = ImageOps.exif_transpose(image)

        if image_format not in {"JPEG", "JPG", "PNG"}:
            if hasattr(uploaded_file, "seek") and original_position is not None:
                uploaded_file.seek(original_position)
            return uploaded_file

        if hasattr(image, "info"):
            image.info.pop("exif", None)
            image.info.pop("icc_profile", None)
            image.info.pop("comment", None)

        if image_format in {"JPEG", "JPG"}:
            sanitized = image.convert("RGB")
            save_kwargs = {
                "format": "JPEG",
                "quality": 95,
                "subsampling": 0,
                "optimize": True,
                "exif": b"",
            }
        else:  # PNG
            target_mode = (
                "RGBA"
                if ("A" in image.mode or image.info.get("transparency"))
                else "RGB"
            )
            sanitized = image.convert(target_mode)
            save_kwargs = {
                "format": "PNG",
                "optimize": True,
            }

        buffer = BytesIO()
        try:
            sanitized.save(buffer, **save_kwargs)
        except (OSError, ValueError):
            buffer = BytesIO()
            if image_format in {"JPEG", "JPG"}:
                sanitized.save(
                    buffer,
                    format="JPEG",
                    quality=90,
                    subsampling=0,
                    exif=b"",
                )
            else:
                sanitized.save(
                    buffer,
                    format="PNG",
                )

        buffer.seek(0)

        if hasattr(uploaded_file, "close"):
            try:
                uploaded_file.close()
            except Exception:
                pass

        content_type = getattr(uploaded_file, "content_type", None) or mime_type
        return SimpleUploadedFile(
            name=getattr(uploaded_file, "name", "logo"),
            content=buffer.getvalue(),
            content_type=content_type,
        )
    finally:
        if sanitized is not None:
            sanitized.close()
        if image is not None:
            image.close()


class PaperlessAuthTokenSerializer(AuthTokenSerializer):
    code = serializers.CharField(
        label="MFA Code",
        write_only=True,
        required=False,
    )

    def validate(self, attrs):
        attrs = super().validate(attrs)
        user = attrs.get("user")
        code = attrs.get("code")
        mfa_adapter = get_mfa_adapter()
        if mfa_adapter.is_mfa_enabled(user):
            if not code:
                raise serializers.ValidationError(
                    "MFA code is required",
                )
            authenticator = Authenticator.objects.get(
                user=user,
                type=Authenticator.Type.TOTP,
            )
            if not TOTP(instance=authenticator).validate_code(
                code,
            ):
                raise serializers.ValidationError(
                    "Invalid MFA code",
                )
        return attrs


class UserSerializer(serializers.ModelSerializer):
    password = ObfuscatedPasswordField(required=False)
    user_permissions = serializers.SlugRelatedField(
        many=True,
        queryset=Permission.objects.exclude(content_type__app_label="admin"),
        slug_field="codename",
        required=False,
    )
    inherited_permissions = serializers.SerializerMethodField()
    is_mfa_enabled = serializers.SerializerMethodField()

    def get_is_mfa_enabled(self, user: User) -> bool:
        mfa_adapter = get_mfa_adapter()
        return mfa_adapter.is_mfa_enabled(user)

    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "email",
            "password",
            "first_name",
            "last_name",
            "date_joined",
            "is_staff",
            "is_active",
            "is_superuser",
            "groups",
            "user_permissions",
            "inherited_permissions",
            "is_mfa_enabled",
        )

    def get_inherited_permissions(self, obj) -> list[str]:
        return obj.get_group_permissions()

    def update(self, instance, validated_data):
        if "password" in validated_data:
            if len(validated_data.get("password").replace("*", "")) > 0:
                instance.set_password(validated_data.get("password"))
                instance.save()
            validated_data.pop("password")
        super().update(instance, validated_data)
        return instance

    def create(self, validated_data):
        groups = None
        if "groups" in validated_data:
            groups = validated_data.pop("groups")
        user_permissions = None
        if "user_permissions" in validated_data:
            user_permissions = validated_data.pop("user_permissions")
        password = None
        if (
            "password" in validated_data
            and len(validated_data.get("password").replace("*", "")) > 0
        ):
            password = validated_data.pop("password")
        user = User.objects.create(**validated_data)
        # set groups
        if groups:
            user.groups.set(groups)
        # set permissions
        if user_permissions:
            user.user_permissions.set(user_permissions)
        # set password
        if password:
            user.set_password(password)
        user.save()
        return user


class GroupSerializer(serializers.ModelSerializer):
    permissions = serializers.SlugRelatedField(
        many=True,
        queryset=Permission.objects.exclude(content_type__app_label="admin"),
        slug_field="codename",
    )

    class Meta:
        model = Group
        fields = (
            "id",
            "name",
            "permissions",
        )


class SocialAccountSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()

    class Meta:
        model = SocialAccount
        fields = (
            "id",
            "provider",
            "name",
        )

    def get_name(self, obj: SocialAccount) -> str:
        try:
            return obj.get_provider_account().to_str()
        except SocialApp.DoesNotExist:
            return "Unknown App"


class ProfileSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(allow_blank=True, required=False)
    password = ObfuscatedPasswordField(required=False, allow_null=False)
    auth_token = serializers.SlugRelatedField(read_only=True, slug_field="key")
    social_accounts = SocialAccountSerializer(
        many=True,
        read_only=True,
        source="socialaccount_set",
    )
    is_mfa_enabled = serializers.SerializerMethodField()
    has_usable_password = serializers.SerializerMethodField()

    def get_is_mfa_enabled(self, user: User) -> bool:
        mfa_adapter = get_mfa_adapter()
        return mfa_adapter.is_mfa_enabled(user)

    def get_has_usable_password(self, user: User) -> bool:
        return user.has_usable_password()

    class Meta:
        model = User
        fields = (
            "email",
            "password",
            "first_name",
            "last_name",
            "auth_token",
            "social_accounts",
            "has_usable_password",
            "is_mfa_enabled",
        )


class ApplicationConfigurationSerializer(serializers.ModelSerializer):
    user_args = serializers.JSONField(binary=True, allow_null=True)
    barcode_tag_mapping = serializers.JSONField(binary=True, allow_null=True)

    def run_validation(self, data):
        # Empty strings treated as None to avoid unexpected behavior
        if "user_args" in data and data["user_args"] == "":
            data["user_args"] = None
        if "barcode_tag_mapping" in data and data["barcode_tag_mapping"] == "":
            data["barcode_tag_mapping"] = None
        if "language" in data and data["language"] == "":
            data["language"] = None
        return super().run_validation(data)

    def update(self, instance, validated_data):
        if instance.app_logo and "app_logo" in validated_data:
            instance.app_logo.delete()
        return super().update(instance, validated_data)

    def validate_app_logo(self, file):
        if not file:
            return file

        if hasattr(file, "seek"):
            file.seek(0)
        mime_type = magic.from_buffer(file.read(2048), mime=True)
        if hasattr(file, "seek"):
            file.seek(0)

        if mime_type == "image/svg+xml":
            reject_dangerous_svg(file)
            if hasattr(file, "seek"):
                file.seek(0)
            return file

        return strip_image_metadata(file, mime_type)

    class Meta:
        model = ApplicationConfiguration
        fields = "__all__"
