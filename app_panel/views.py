from django.shortcuts import render
from rest_framework import viewsets
from utils.base_authentication import JWTAuthentication
from user_authentication.user_controller import *
from rest_framework.permissions import AllowAny
from app_panel.apps_controller import AppController, SubscriptionController, PlanController
from app_panel.serializers import AppsSerializer, planSerializer, SubscriptionSerializer

app_controller = AppController()
subscription_controller = SubscriptionController()
plan_controller = PlanController()
class AppView(viewsets.ModelViewSet):
    """
    Endpoints for department CRUDs.
    """

    authentication_classes = (JWTAuthentication,)
    serializer_class = AppsSerializer

    def create_record(self, request):
        return app_controller.create_app(request)

    def get_records(self, request):
        return app_controller.get_app(request)

    def update_record(self, request):
        return app_controller.update_app(request)

    def delete_records(self, request):
        return app_controller.delete_app(request)

class SubscriptionView(viewsets.ModelViewSet):
    """
    Endpoints for department CRUDs.
    """

    authentication_classes = (JWTAuthentication,)
    serializer_class = SubscriptionSerializer

    def create_record(self, request):
        return subscription_controller.create_subscription(request)

    def get_records(self, request):
        return subscription_controller.get_subscription(request)

    def update_record(self, request):
        return subscription_controller.update_subscription(request)

    def cancel_subscription(self, request):
        return subscription_controller.cancel_subscription(request)

    def delete_records(self, request):
        return subscription_controller.delete_subscription(request)

class PlanView(viewsets.ModelViewSet):
    """
    Endpoints for department CRUDs.
    """

    authentication_classes = (JWTAuthentication,)
    serializer_class = planSerializer

    def create_record(self, request):
        return plan_controller.create_plan(request)

    def get_records(self, request):
        return plan_controller.get_plan(request)

    def update_record(self, request):
        return plan_controller.update_plan(request)

    def delete_records(self, request):
        return plan_controller.delete_plan(request)
