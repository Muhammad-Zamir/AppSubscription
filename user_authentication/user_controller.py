import json
import threading

from django.db.models import Q
from django.contrib.auth import authenticate
from django.db import transaction
from django.utils import timezone
from app_subscription.settings import EMAIL_HOST_USER
from utils.send_email import *
from utils.helper import *
from copy import deepcopy
from .models import Token, User, EmailTemplate
from .serializers import ChangePasswordSerializer, ForgetPasswordSerializer, VerifyOtpSerializer, \
    UserSerializerFullName, LoginSerializer , UserProfileSerializer
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.core.mail import send_mail

# Create your views here.
class RegistrationController:

    def create_user(self, request):

        email = request.data.get("email")
        password = request.data.get("password")
        username = request.data.get("username")
        hashed_password = make_password(password)

        print(email)
        print(password)

        if not email or not password:
            return create_response({}, message=PROVIDE_BOTH, status_code=400)

        try:
            if User.objects.filter(email=email).exists():
                return create_response({}, message=USER_ALREADY_EXISTS, status_code=400)

            request.data['password'] = hashed_password

            user = User.objects.create_user(username=username, email=email, password=hashed_password, is_active=False)

            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            #verification_link = 'http://127.0.0.1:8000//verify/ {uid}/{token}/'
            verification_link = f'http://127.0.0.1:8000/register-user?uidb64={uid}&token={token}'
            # Update with your website's URL
            print("uid", uid)
            print("token", token)
            subject = 'Email Verification'
            message = f'Click the following link to verify your email: {verification_link}'
            from_email = settings.EMAIL_HOST_USER
            recipient_list = [email]

            send_mail(subject, message, from_email, recipient_list)
            return create_response({}, message=SUCCESSFUL, status_code=200)
        except Exception as e:
            return Response({'error': str(e)}, status=400)

    def get_email_verification(self, request):
        try:
            uidb64 = get_query_param(request, "uidb64", None)
            token = get_query_param(request, "token", None)
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(id=uid)

            if default_token_generator.check_token(user, token):
                user.is_active = True
                user.save()
                subject = "Registered"
                message = f"""
                Hi {user.username},
                Your request for registration has been verified. 
                Please use your login credentials in order to use the system.
                Thankyou!
                """
                from_email = settings.EMAIL_HOST_USER
                recipient_list = [user.email]

                send_mail(subject, message, from_email, recipient_list)
                return create_response({}, message=EMAIL_VERIFIED, status_code=200)
            else:
                return create_response({}, message=INVALID_TOKEN, status_code=400)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return create_response({}, message=INAVLID_LINK, status_code=400)
class LoginController:
    feature_name = "Auth"
    """
    An endpoint for Login
    """
    serializer_class = LoginSerializer

    def login(self, request):
        request.POST._mutable = True
        request.data["email"] = request.data.get("email", "").strip()
        request.data["password"] = request.data.get("password", "").strip()
        request.POST._mutable = False
        email = request.data.get("email")
        password = request.data.get("password")
        serialized_data = self.serializer_class(data=request.data)
        if not serialized_data.is_valid():
            return create_response({},
                                   get_first_error_message_from_serializer_errors(serialized_data.errors, UNSUCCESSFUL),
                                   status_code=401)
        user = authenticate(username=email, password=password)
        if not user or user.is_deleted:
            return create_response({}, message=INCORRECT_EMAIL_OR_PASSWORD, status_code=401)
        response_data = {
            "token": user.get_access_token(),
            "name": user.get_full_name(),
            "role": "is_superuser",
            "id": user.id
        }
        Token.objects.update_or_create(defaults={"token": response_data.get("token")}, user_id=user.id)
        user.failed_login_attempts = 0
        user.last_failed_time = None
        user.last_login = timezone.now()
        user.save()
        return create_response(response_data, SUCCESSFUL, status_code=200)


class ChangePasswordController:
    feature_name = "Change Password"
    """
    An endpoint for changing password.
    """

    serializer_class = ChangePasswordSerializer

    def update(self, request):
        request.POST._mutable = True
        request.data["old_password"] = request.data.get("old_password").strip()
        request.data["new_password"] = request.data.get("new_password").strip()
        request.data["confirm_password"] = request.data.get("confirm_password").strip()
        request.POST._mutable = True
        serializer = self.serializer_class(data=request.data, context={"user": request.user})
        if not serializer.is_valid():
            return create_response({}, get_first_error_message_from_serializer_errors(serializer.errors, UNSUCCESSFUL),
                                   status_code=400)
        if request.data.get('new_password') != request.data.get('confirm_password'):
            return create_response({}, message=PASSWORD_DOES_NOT_MATCH, status_code=403)

        if not request.user.check_password(request.data.get("old_password")):
            return create_response({}, message=INCORRECT_OLD_PASSWORD, status_code=400)

        request.user.set_password(request.data.get("new_password"))
        request.user.save()
        return create_response({}, SUCCESSFUL, status_code=200)


class ForgetPasswordController:
    feature_name = "Forget Password"
    serializer_class = ForgetPasswordSerializer

    def forget_password(self, request):
        serialized_data = self.serializer_class(data=request.data)
        if not serialized_data.is_valid():
            return create_response({},
                                   get_first_error_message_from_serializer_errors(serialized_data.errors, UNSUCCESSFUL),
                                   401)
        try:
            user = User.objects.filter(email__iexact=request.data.get("email")).first()
            if not user:
                return create_response({}, USER_NOT_FOUND, status_code=404)
            # generate OTP
            otp = generate_six_length_random_number()
            user.otp = otp
            user.otp_generated_at = timezone.now()
            user.save()
            if (template := EmailTemplate.objects.filter(notification_feature__name=self.feature_name,
                                                         is_published=True,
                                                         is_deleted=False)).exists():
                template = template.first()
                variables = {
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "otp": user.otp
                }
                message = pass_variables_into_string(template.body, variables)
                message = message.replace("/n", "\n\n")
                subject = template.subject

            else:
                subject = "Password Recovery Request"
                message = f"""
                            OTP: {otp}
                        """

            recipient_list = [request.data.get("email")]
            t = threading.Thread(target=send_mail, args=(subject, message, EMAIL_HOST_USER, recipient_list))
            t.start()
            return create_response({}, EMAIL_SUCCESSFULLY_SENT, status_code=200)

        except Exception as e:
            print(e)
            return create_response({}, e, status_code=500)


class VerifyOtpController:
    feature_name = "OTP verification"
    serializer_class = VerifyOtpSerializer

    def verify(self, request):
        request.POST._mutable = True
        request.data["new_password"] = request.data.get("new_password").strip()
        request.data["confirm_password"] = request.data.get("confirm_password").strip()
        request.POST._mutable = True
        try:
            time_delay = timezone.now() - timezone.timedelta(seconds=300)
            user = User.objects.filter(otp=request.data.get("otp"), otp_generated_at__gt=time_delay).first()
            if not user:
                return create_response({}, INVALID_OTP, status_code=404)
            serialized_data = self.serializer_class(data=request.data, context={"user": user})
            if not serialized_data.is_valid():
                return create_response({}, get_first_error_message_from_serializer_errors(serialized_data.errors,
                                                                                          UNSUCCESSFUL), 401)
            if request.data.get('new_password') != request.data.get('confirm_password'):
                return create_response({}, message=PASSWORD_DOES_NOT_MATCH, status_code=403)
            user.set_password(request.data.get("new_password"))
            user.otp = None
            user.save()
            return create_response({}, SUCCESSFUL, status_code=200)
        except Exception as e:
            print(e)
            return create_response({}, e, status_code=500)


class UserListingController:
    feature_name = "User"
    serializer_class = UserListingSerializer

    def get_user(self, request):
        self.serializer_class = UserSerializerFullName if request.query_params.get(
            "api_type") == "list" else UserListingSerializer
        kwargs = {}
        search_kwargs = {}
        id = get_query_param(request, "id", None)
        order = get_query_param(request, 'order', 'desc')
        order_by = get_query_param(request, 'order_by', "created_at")
        search = get_query_param(request, 'search', None)
        export = get_query_param(request, 'export', None)
        profile = get_query_param(request, "self", None)
        is_active = get_query_param(request, "is_active", None)
        role = get_query_param(request, "role", None)


        if is_active:
            kwargs["is_active"] = is_active
        if id:
            kwargs["id"] = id
        if profile:
            kwargs["id"] = request.user.id
        if search:
            search_kwargs = seacrh_text_parser(search, search_kwargs)
        if role:
            kwargs["role__name__iexact"] = role
        if order and order_by:
            if order == "desc":
                order_by = f"-{order_by}"
        kwargs["is_deleted"] = False
        if request.user.is_superuser:

            data = self.serializer_class.Meta.model.objects.filter(Q(**search_kwargs, _connector=Q.OR), **kwargs).order_by(
                order_by)
        else:
            data = self.serializer_class.Meta.model.objects.filter(Q(**search_kwargs, _connector=Q.OR), **kwargs).order_by(
                order_by)

        count = data.count()
        data = paginate_data(data, request)

        serialized_data = self.serializer_class(data, many=True).data
        response_data = {
            "count": count,
            "data": serialized_data
        }
        return create_response(response_data, SUCCESSFUL, status_code=200)

    def create_user(self, request):
        try:
            dummy_password = generate_dummy_password()
            request.POST._mutable = True
            request.data["password"] = make_password(dummy_password)
            request.POST._mutable = True
            serialized_data = self.serializer_class(data=request.data)
            if serialized_data.is_valid():
                response_data = serialized_data.save()
            else:
                return create_response({}, get_first_error_message_from_serializer_errors(serialized_data.errors,
                                                                                          UNSUCCESSFUL),
                                       status_code=500)
            send_password(first_name=response_data.first_name, last_name=response_data.last_name,
                          email=request.data.get("email"),
                          password=dummy_password)
            return create_response(self.serializer_class(response_data).data, SUCCESSFUL, status_code=200)
        except Exception as e:
            print(e)
            return create_response({}, UNSUCCESSFUL, 500)

    def update_user(self, request):
        try:
            if "id" not in request.data:
                return create_response({}, ID_NOT_PROVIDED, 404)
            else:
                instance = self.serializer_class.Meta.model.objects.filter(id=request.data.get("id"),
                                                                           is_deleted=False)
                if not instance:
                    return create_response({}, USER_NOT_FOUND, 400)
                instance = instance.first()
                serialized_data = self.serializer_class(instance, data=request.data, partial=True)
                if serialized_data.is_valid():
                    response_data = serialized_data.save()
                    check_for_children(instance, data=response_data, request=request)

                    return create_response(self.serializer_class(response_data).data, SUCCESSFUL, 200)
                return create_response({}, get_first_error_message_from_serializer_errors(serialized_data.errors,
                                                                                          UNSUCCESSFUL),
                                       status_code=500)
        except Exception as e:
            return create_response({}, UNSUCCESSFUL, status_code=500)

    def delete_user(self, request):
        if "id" not in request.query_params:
            return create_response({}, ID_NOT_PROVIDED, 404)
        ids = ast.literal_eval(request.query_params.get("id"))
        instances = self.serializer_class.Meta.model.objects.filter(id__in=ids,
                                                                    is_deleted=False)
        if not instances:
            return create_response({}, USER_NOT_FOUND, 404)
        instances.update(is_deleted=True, deleted_at=timezone.now())
        return create_response({}, SUCCESSFUL, 200)


class LogoutController:

    def logout(self, request):
        try:
            instance = Token.objects.filter(user=request.user.id, is_deleted=False).first()

            instance.token = ''
            instance.device_token = None
            instance.save()

            return create_response({}, SUCCESSFUL, 200)


        except Exception as e:
            return create_response({'error': str(e)}, SOMETHING_WENT_WRONG, 500)

class UserProfileController:
    serializer_class = UserProfileSerializer
    def get_profile(self, request):

        kwargs = {}
        user = request.user
        if user:
            kwargs["username"] = user
        print("request.user", user)
        kwargs["is_deleted"] = False
        data = self.serializer_class.Meta.model.objects.filter(**kwargs)
        print(data)
        serialized_data = self.serializer_class(data, many=True).data
        response_data = {
            "data": serialized_data
        }
        return create_response(response_data, SUCCESSFUL, status_code=200)

    def update_profile(self, request):
        try:
            kwargs = {}
            user = request.user
            if user:
                kwargs["username"] = user
            password = request.data.get("password")
            if password:
                hashed_password = make_password(password)
                request.data['password'] = hashed_password

            kwargs["is_deleted"] = False

            instance = self.serializer_class.Meta.model.objects.filter(**kwargs)
            if not instance:
                return create_response({}, USER_NOT_FOUND, 400)
            instance = instance.first()
            serialized_data = self.serializer_class(instance, data=request.data, partial=True)
            if serialized_data.is_valid():
                response_data = serialized_data.save()
                check_for_children(instance, data=response_data, request=request)

                return create_response(self.serializer_class(response_data).data, SUCCESSFUL, 200)
            return create_response({}, get_first_error_message_from_serializer_errors(serialized_data.errors,
                                                                                          UNSUCCESSFUL),
                                       status_code=500)
        except Exception as e:
            print(e)
            return create_response({}, UNSUCCESSFUL, status_code=500)
    def delete_profile(self, request):
        kwargs = {}
        user = request.user
        if user:
            kwargs["username"] = user
        kwargs["is_deleted"] = False
        instances = self.serializer_class.Meta.model.objects.filter(**kwargs)
        if not instances:
            return create_response({}, USER_NOT_FOUND, 404)
        instances.update(is_deleted=True, deleted_at=timezone.now())
        return create_response({}, SUCCESSFUL, 200)