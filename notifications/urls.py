"""
LCLPD_backend URL Configuration
"""
from django.urls import path
from .views import *

urlpatterns = [
    path(
        "email",
        EmailTempleteListingView.as_view(
            {"get": "get", "post": "create", "patch": "update", "delete": "destroy"}
        ),
    ),
    path(
        "notification_features",
        NotificationFeaturesListingView.as_view(
            {"get": "get", "post": "create", "patch": "update","delete": "destroy"}
        ),
    )

    # path(
    #     "notify",
    #     NotifyView.as_view(
    #         {"post": "create"}
    #     ),
    # ),
]
