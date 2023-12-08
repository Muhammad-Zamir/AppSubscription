from rest_framework import serializers
from app_panel.models import App, Subscription, plan

class planSerializer(serializers.ModelSerializer):
    class Meta:
        model = plan
        fields = ["id", "name", "price"]



class SubscriptionSerializer(serializers.ModelSerializer):
    plan = planSerializer(read_only=True)
    class Meta:
        model = Subscription
        fields = ["id", "app", "is_active", "user","plan"]


class AppsSerializer(serializers.ModelSerializer):
    subscriptions = SubscriptionSerializer(many=True, read_only=True)
    class Meta:
        model = App
        exclude = ["description"]