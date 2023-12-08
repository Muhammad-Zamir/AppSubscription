from user_authentication.models import *
from django.contrib.auth.hashers import check_password
from utils.custom_exceptions import *
from django.db.models import Q, Count
from rest_framework import serializers


from user_authentication.models import Token



class LoginSerializer(serializers.Serializer):
    """User login serializer
    """
    email = serializers.EmailField(
        label=("email"),
        write_only=True
    )
    password = serializers.CharField(
        label=("password"),
        style={"input_type": "password"},
        trim_whitespace=False,
        write_only=True
    )

    def validate(self, instance):
        if len(instance["password"]) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if User.objects.filter(email=instance["email"], is_active="INACTIVE").exists():
            raise serializers.ValidationError("Your account has been deactivated.")

        return instance


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint.
    """

    old_password = serializers.CharField(
        label=("old_password"),
        style={"input_type": "old_password"},
        trim_whitespace=False,
        write_only=True
    )

    new_password = serializers.CharField(
        label=("new_password"),
        style={"input_type": "new_password"},
        trim_whitespace=False,
        write_only=True
    )

    confirm_password = serializers.CharField(
        label=("confirm_password"),
        style={"input_type": "confirm_password"},
        trim_whitespace=False,
        write_only=True
    )

    def validate(self, instance):
        user = self.context.get("user")
        if len(instance["new_password"]) < 8:
            raise PasswordMustBeEightChar()
        if instance["new_password"] == instance["old_password"]:
            raise SameOldPassword()
        passwords = UserPasswordHistory.objects.filter(user=user.id).order_by(
            "-created_at")
        if passwords:
            passwords = passwords[:6] if len(passwords) >= 6 else passwords
            for p in passwords:
                if check_password(instance["new_password"], p.password):
                    raise PasswordAlreadyUsed()
        return instance


class VerifyOtpSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint.
    """
    otp = serializers.CharField(
        label=("otp"),
        style={"input_type": "otp"},
        trim_whitespace=False,
        write_only=True
    )

    new_password = serializers.CharField(
        label=("new_password"),
        style={"input_type": "new_password"},
        trim_whitespace=False,
        write_only=True
    )

    confirm_password = serializers.CharField(
        label=("confirm_password"),
        style={"input_type": "confirm_password"},
        trim_whitespace=False,
        write_only=True
    )

    def validate(self, instance):
        user = self.context.get("user")
        if len(instance["new_password"]) < 8:
            raise PasswordMustBeEightChar()
        passwords = UserPasswordHistory.objects.filter(user=user.id).order_by(
            "-created_at")
        if passwords:
            passwords = passwords[:6] if len(passwords) >= 6 else passwords
            for p in passwords:
                if check_password(instance["new_password"], p.password):
                    raise serializers.ValidationError("This password has already been used in the last 6 passwords.")
        return instance


class ForgetPasswordSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint.
    """
    email = serializers.EmailField(
        label=("email"),
        write_only=True
    )



class UserListingSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"
        extra_kwargs = {'password': {'write_only': True}, "otp": {'write_only': True},
                        "otp_generated_at": {'write_only': True},
                        "failed_login_attempts": {'write_only': True}, "last_failed_time": {'write_only': True}}



# class DeviceTokenSerializerCustom(serializers.ModelSerializer):
#     class Meta:
#         model = Token
#         fields = ['device_token']
#
#
# class DeviceTokenSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Token
#         fields = '__all__'


class UserSerializerFullName(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "full_name"]

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}"

class OrganizationSerializer(serializers.ModelSerializer):
    message_quota = serializers.SerializerMethodField()
    def get_message_quota(self, instance):
        try:
            message_quota_object = instance.consumed_organization.first()
            if message_quota_object:
                message_quota = {
                    'remaining_quota': message_quota_object.remaining_quota,
                    'total_quota': message_quota_object.total_quota,
                }
            else:
                message_quota = None
        except Exception as e:
            message_quota = None
        return message_quota
    class Meta:
        model = Organization
        fields = "__all__"


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"