from django.core.validators import RegexValidator
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.contrib.auth.hashers import make_password
from django.db.models import UniqueConstraint, Q

from app_subscription.settings import AUTH_USER_MODEL
from utils.base_models import LogsMixin
from utils.reusable_methods import generate_access_token


# Create your models here.
class Organization(LogsMixin):
    name = models.CharField(
        max_length=50,
        validators=[
            RegexValidator(
                r"^[a-zA-Z0-9 ]+$",
                message="Name field should not contain special characters",
            )
        ], unique= True
    )
    admin = models.ForeignKey(AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, related_name="reporting_user", blank=True)
    email = models.EmailField(unique=True,blank=True,null=True)
    address = models.CharField(max_length=500, blank=True, null=True)
    logo = models.ImageField(upload_to="Images/", blank=True, null=True)


class User(LogsMixin, AbstractUser):
    """Fully featured User model, email and password are required.
    Other fields are optional.
    """
    status_choices = (
        ("INACTIVE", "INACTIVE"),
        ("ACTIVE", "ACTIVE"),
    )

    first_name = models.CharField(max_length=50, blank=True, null=True)
    last_name = models.CharField(max_length=50, blank=True, null=True)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=50, null=True, blank=True,unique=True)
    is_active = models.CharField(max_length=8, default="ACTIVE", choices=status_choices)
    contact_number = models.CharField(max_length=20, validators=[
        RegexValidator(r'^[^a-zA-Z]+$', message="Contact field should not contain alphabet characters")],unique=True, blank=True, null=True)
    otp = models.IntegerField(null=True, blank=True)
    last_login = models.DateTimeField(null=True, blank=True)
    otp_generated_at = models.DateTimeField(null=True, blank=True)
    REQUIRED_FIELDS = ["email", "password"]
    failed_login_attempts = models.IntegerField(default=0)
    last_failed_time = models.DateTimeField(null=True, blank=True)

    def get_access_token(self):
        return generate_access_token(self)

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

    def set_password(self, raw_password):
        # Store the new password in the password history
        UserPasswordHistory.objects.create(
            user=self, password=make_password(raw_password)
        )
        super().set_password(raw_password)

class Token(LogsMixin):
    user = models.ForeignKey(
        AUTH_USER_MODEL, null=False, blank=False, on_delete=models.CASCADE, related_name="token"
    )
    token = models.TextField(max_length=500, unique=True, null=False, blank=False)
    device_token = models.TextField(max_length=1000, unique=True, null=True, blank=True)

class UserPasswordHistory(LogsMixin):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    password = models.CharField(max_length=128)

class NotificationFeatures(LogsMixin):
    """Model for storing features"""

    name = models.TextField(max_length=50, validators=[
        RegexValidator(r'^[a-zA-Z0-9 ]+$', message="Name field should not contain special characters")])

    class Meta:
        constraints = [
            UniqueConstraint(
                fields=["name", "is_deleted"],
                name="unique_notification_feature",
                condition=Q(is_deleted="f"),
            )
        ]
class EmailTemplate(LogsMixin):
    name = models.CharField(max_length=500)
    subject = models.TextField(max_length=500)
    body = models.TextField()
    is_published = models.BooleanField(default=True)
    notification_feature = models.ForeignKey(NotificationFeatures, on_delete=models.CASCADE,
                                             related_name="notification_feature_name", blank=True, null=True)
