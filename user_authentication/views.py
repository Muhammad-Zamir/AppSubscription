from rest_framework import viewsets
from utils.base_authentication import JWTAuthentication
from user_authentication.serializers import LoginSerializer, ChangePasswordSerializer, \
    ForgetPasswordSerializer, VerifyOtpSerializer, UserProfileSerializer
from user_authentication.user_controller import *
from rest_framework.permissions import AllowAny
from user_authentication.permission import IsSuperAdmin, IsAdmin

# Create your views here.
reg_user = RegistrationController()
login_controller = LoginController()
forget_password_controller = ForgetPasswordController()
change_password_controller = ChangePasswordController()
verify_otp = VerifyOtpController()
role_controller = RoleController()
user_controller = UserListingController()
device_token_controller = DeviceTokenController()
logout_controller = LogoutController()
organization_controller = OrganizationController()
user_profile_controller = UserProfileController()

class UserRegAPI(viewsets.ModelViewSet):
    permission_classes = [AllowAny]
    def post(self, request):
        return reg_user.create_user(request)
    def get(self, request):
        return reg_user.get_email_verification(request)
class LoginAPIView(viewsets.ModelViewSet):
    """
        An endpoint for user login.
        """
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        return login_controller.login(request)


class ChangePasswordAPI(viewsets.ModelViewSet):
    """
    An endpoint for changing password.
    """
    authentication_classes = (JWTAuthentication,)
    serializer_class = ChangePasswordSerializer

    def patch(self, request):
        return change_password_controller.update(request)


class ForgetPasswordAPI(viewsets.ModelViewSet):
    """
    An endpoint for forget password.
    """
    permission_classes = [AllowAny]
    serializer_class = ForgetPasswordSerializer

    def post(self, request):
        return forget_password_controller.forget_password(request)


class VerifyOtpAPI(viewsets.ModelViewSet):
    """
    An endpoint for token verification.
    """
    permission_classes = [AllowAny]
    serializer_class = VerifyOtpSerializer

    def post(self, request):
        return verify_otp.verify(request)

class RoleListingView(viewsets.ModelViewSet):
    """
    Endpoints for role CRUDs.
    """
    authentication_classes = (JWTAuthentication,)
    serializer_class = RoleSerializer
    permission_classes = [IsSuperAdmin]

    def get(self, request):
        return role_controller.get_role(request)

    def create(self, request):
        return role_controller.create_role(request)

    def update(self, request):
        return role_controller.update_role(request)

    def destroy(self, request):
        return role_controller.delete_role(request)

class UserListingView(viewsets.ModelViewSet):
    """
    Endpoints for users CRUDs.
    """
    authentication_classes = (JWTAuthentication,)
    serializer_class = UserListingSerializer
    permission_classes = [IsAdmin]

    def get(self, request):
        return user_controller.get_user(request)

    def create(self, request):
        return user_controller.create_user(request)

    def update(self, request):
        return user_controller.update_user(request)

    def destroy(self, request):
        return user_controller.delete_user(request)
class DeviceTokenView(viewsets.ModelViewSet):
    authentication_classes = (JWTAuthentication,)

    def create(self,request):
        return device_token_controller.create(request)

class LogoutView(viewsets.ModelViewSet):
    authentication_classes = (JWTAuthentication,)

    def logout(self, request):
        return logout_controller.logout(request)

class OrganizationListingView(viewsets.ModelViewSet):
    """
    Endpoints for department CRUDs.
    """

    authentication_classes = (JWTAuthentication,)
    serializer_class = OrganizationSerializer
    permission_classes = [IsSuperAdmin]


    def create(self, request):
        return organization_controller.create_organization(request)

    def destroy(self, request):
        return organization_controller.delete_organization(request)
class GetOrganizationListingView(viewsets.ModelViewSet):
    """
    Endpoints for department CRUDs.
    """

    authentication_classes = (JWTAuthentication,)
    serializer_class = OrganizationSerializer
    permission_classes = [IsAdmin]

    def get(self, request):
        return organization_controller.get_organization(request)

    def update(self, request):
        return organization_controller.update_organization(request)


class UserProfileView(viewsets.ModelViewSet):
    """
    Endpoints for users CRUDs.
    """
    serializer_class = UserProfileSerializer
    authentication_classes = (JWTAuthentication,)
    def get(self, request):
        return user_profile_controller.get_profile(request)

    def update(self, request):
        return user_profile_controller.update_profile(request)

    def destroy(self, request):
        return user_profile_controller.delete_profile(request)