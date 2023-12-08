from django.db import models

from user_authentication.models import User
from utils.base_models import LogsMixin


# Create your models here.
class App(LogsMixin):
    name = models.CharField(max_length=500)
    description = models.TextField()
    user = models.ForeignKey(User, on_delete=models.CASCADE,
                             related_name="apps", blank=True, null=True)


class Subscription(LogsMixin):
    app = models.ForeignKey(App, on_delete=models.CASCADE,
                            related_name="subscriptions")
    is_active = models.BooleanField(default=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE,
                             related_name="user_subscriptions")
    plan = models.ForeignKey("plan", on_delete=models.CASCADE,
                             related_name="subscriptions")


class plan(LogsMixin):
    name = models.CharField(max_length=50)
    price = models.CharField(max_length=10)
