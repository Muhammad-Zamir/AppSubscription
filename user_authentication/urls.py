"""
LCLPD_backend URL Configuration
"""
from django.urls import path
from .views import *
from user_authentication import views

urlpatterns = [
    path('register-user', UserRegAPI.as_view({"post": "post","get": "get",})),
    path('login', LoginAPIView.as_view({"post": "post"})),
    path('change-password', ChangePasswordAPI.as_view({"post": "patch"})),
    path('forget-password', ForgetPasswordAPI.as_view({"post": "post"})),
    path('verify_otp', VerifyOtpAPI.as_view({"post": "post"})),
    path('logout', LogoutView.as_view({"post": "logout"})),

    path('user', UserListingView.as_view(
        {
            "get": "get",
            "post": "create",
            "patch": "update",
            "delete": "destroy"
        }
    )
         ),

    path('profile', UserProfileView.as_view(
        {
            "get": "get",
            "patch": "update",
            "delete": "destroy"
        }
    )
         ),
]
