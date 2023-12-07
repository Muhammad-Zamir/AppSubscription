import json
import threading

from django.db.models import Q
from django.contrib.auth import authenticate
from django.db import transaction
from django.utils import timezone
from app_subscription.settings import EMAIL_HOST_USER
from utils.export_columns import *
from utils.send_email import *
from utils.export_utils import ExportUtility
from utils.helper import *
from copy import deepcopy
from .models import Token, User, EmailTemplate
from .serializers import ChangePasswordSerializer, ForgetPasswordSerializer, VerifyOtpSerializer, \
    UserSerializerFullName, RoleSerializer, DeviceTokenSerializerCustom, LoginSerializer, OrganizationSerializer , UserProfileSerializer
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
            # Check if a user with the same email already exists
            if User.objects.filter(email=email).exists():
                return create_response({}, message=USER_ALREADY_EXISTS, status_code=400)

            # Generate an email verification token
            request.data['password'] = hashed_password

            user = User.objects.create_user(username=username, email=email, password=hashed_password, is_active=False)

            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            # Send an email with a link that includes the token and UID
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
        # make the request data mutable
        request.POST._mutable = True
        # strip whitespace from the email and password
        request.data["email"] = request.data.get("email", "").strip()
        request.data["password"] = request.data.get("password", "").strip()
        # make the request data mutable
        request.POST._mutable = False
        # Get email and password from request data
        email = request.data.get("email")
        password = request.data.get("password")
        # create the serializer instance
        serialized_data = self.serializer_class(data=request.data)
        # check if the data is valid
        if not serialized_data.is_valid():
            # if not valid return an error message
            return create_response({},
                                   get_first_error_message_from_serializer_errors(serialized_data.errors, UNSUCCESSFUL),
                                   status_code=401)
        # authenticate user
        user = authenticate(username=email, password=password)
        if not user or user.is_deleted:
            # if not valid user return an error message
            return create_response({}, message=INCORRECT_EMAIL_OR_PASSWORD, status_code=401)
        # prepare response data
        response_data = {
            "token": user.get_access_token(),
            "name": user.get_full_name(),
            # "role": "is_superuser" if user.is_superuser else RoleSerializer(user.role).data,
            "role": "is_superuser",
            "id": user.id
        }
        # update or create token
        Token.objects.update_or_create(defaults={"token": response_data.get("token")}, user_id=user.id)
        user.failed_login_attempts = 0
        user.last_failed_time = None
        user.last_login = timezone.now()
        user.save()
        # return success message
        return create_response(response_data, SUCCESSFUL, status_code=200)


class ChangePasswordController:
    feature_name = "Change Password"
    """
    An endpoint for changing password.
    """

    serializer_class = ChangePasswordSerializer

    def update(self, request):
        # make the request data mutable
        request.POST._mutable = True
        # strip whitespace from the passwords
        request.data["old_password"] = request.data.get("old_password").strip()
        request.data["new_password"] = request.data.get("new_password").strip()
        request.data["confirm_password"] = request.data.get("confirm_password").strip()
        # make the request data mutable
        request.POST._mutable = True
        # create the serializer instance
        serializer = self.serializer_class(data=request.data, context={"user": request.user})
        # check if the data is valid
        if not serializer.is_valid():
            # If the data is not valid, return a response with the errors
            return create_response({}, get_first_error_message_from_serializer_errors(serializer.errors, UNSUCCESSFUL),
                                   status_code=400)
        # check if the new password and confirm password match
        if request.data.get('new_password') != request.data.get('confirm_password'):
            # if not match return error message
            return create_response({}, message=PASSWORD_DOES_NOT_MATCH, status_code=403)

        # Check old password
        if not request.user.check_password(request.data.get("old_password")):
            # if the old password is incorrect return error message
            return create_response({}, message=INCORRECT_OLD_PASSWORD, status_code=400)

        # set_password also hashes the password that the users will get
        request.user.set_password(request.data.get("new_password"))
        request.user.save()
        # return success message
        return create_response({}, SUCCESSFUL, status_code=200)


class ForgetPasswordController:
    feature_name = "Forget Password"
    serializer_class = ForgetPasswordSerializer

    def forget_password(self, request):
        # Deserialize the request data using the defined serializer
        serialized_data = self.serializer_class(data=request.data)
        # check if the request data is valid
        if not serialized_data.is_valid():
            # if invalid return an error message
            return create_response({},
                                   get_first_error_message_from_serializer_errors(serialized_data.errors, UNSUCCESSFUL),
                                   401)
        try:
            # Try to filter the user with the provided email
            user = User.objects.filter(email__iexact=request.data.get("email")).first()
            if not user:
                # if user not found return an error message
                return create_response({}, USER_NOT_FOUND, status_code=404)
            # generate OTP
            otp = generate_six_length_random_number()
            user.otp = otp
            user.otp_generated_at = timezone.now()
            user.save()
            # Prepare the email subject and message
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
            # Send the email
            t = threading.Thread(target=send_mail, args=(subject, message, EMAIL_HOST_USER, recipient_list))
            t.start()
            # return success message
            return create_response({}, EMAIL_SUCCESSFULLY_SENT, status_code=200)

        except Exception as e:
            # print the error message
            print(e)
            # return error message
            return create_response({}, e, status_code=500)


class VerifyOtpController:
    feature_name = "OTP verification"
    serializer_class = VerifyOtpSerializer

    def verify(self, request):
        # make the request data mutable
        request.POST._mutable = True
        # strip whitespace from the passwords
        request.data["new_password"] = request.data.get("new_password").strip()
        request.data["confirm_password"] = request.data.get("confirm_password").strip()
        # make the request data mutable
        request.POST._mutable = True
        try:
            # check OTP time delay
            time_delay = timezone.now() - timezone.timedelta(seconds=300)
            user = User.objects.filter(otp=request.data.get("otp"), otp_generated_at__gt=time_delay).first()
            if not user:
                # if not valid OTP return an error message
                return create_response({}, INVALID_OTP, status_code=404)
            # create the serializer instance
            serialized_data = self.serializer_class(data=request.data, context={"user": user})
            # check if the data is valid
            if not serialized_data.is_valid():
                # if not valid return an error message
                return create_response({}, get_first_error_message_from_serializer_errors(serialized_data.errors,
                                                                                          UNSUCCESSFUL), 401)
            # check if the new password and confirm password match
            if request.data.get('new_password') != request.data.get('confirm_password'):
                # if not match return error message
                return create_response({}, message=PASSWORD_DOES_NOT_MATCH, status_code=403)
            # set new password
            user.set_password(request.data.get("new_password"))
            # clear OTP
            user.otp = None
            user.save()
            # return success message
            return create_response({}, SUCCESSFUL, status_code=200)
        except Exception as e:
            print(e)
            return create_response({}, e, status_code=500)


class UserListingController:
    feature_name = "User"
    serializer_class = UserListingSerializer
    export_util = ExportUtility()

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
        kwargs["is_locked"] = False
        if request.user.role.name == 'Admin':
            organization = get_query_param(request, 'organization', request.user.organization)
            if organization:
                kwargs["organization"] = organization
            data = self.serializer_class.Meta.model.objects.select_related("role").prefetch_related(
                "role").filter(Q(**search_kwargs, _connector=Q.OR), **kwargs).order_by(
                order_by)
        else:
            data = self.serializer_class.Meta.model.objects.select_related("role").prefetch_related(
                "role").filter(Q(**search_kwargs, _connector=Q.OR), **kwargs).order_by(
                order_by)

        if export:
            serialized_data = self.serializer_class(data, many=True)

            return self.export_util.export_user_data(serialized_asset=serialized_data,
                                                     columns=USER_EXPORT_COLUMNS,
                                                     export_name="User Listing")
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


class RoleController:
    feature_name = "Role"
    serializer_class = RoleSerializer
    export_util = ExportUtility()


    def get_role(self, request):
        kwargs = {}
        id = get_query_param(request, "id", None)
        order = get_query_param(request, 'order', 'desc')
        order_by = get_query_param(request, 'order_by', "created_at")
        search = get_query_param(request, 'search', None)
        is_active = get_query_param(request, "is_active", None)
        export = get_query_param(request, "export", None)

        if is_active:
            kwargs["is_active"] = is_active

        if id:
            kwargs["id"] = id
        if search:
            kwargs["name__icontains"] = search
        if order and order_by:
            if order == "desc":
                order_by = f"-{order_by}"
        kwargs["is_deleted"] = False
        data = self.serializer_class.Meta.model.objects.filter(**kwargs).order_by(order_by)
        if export:
            serialized_data = self.serializer_class(data, many=True)
            return self.export_util.export_role_data(
                serialized_asset=serialized_data,
                columns=ROLE_EXPORT_COLUMNS,
                export_name="Role Listing",
            )

        count = data.count()
        data = paginate_data(data, request)

        serialized_data = self.serializer_class(data, many=True).data
        response_data = {
            "count": count,
            "data": serialized_data
        }
        return create_response(response_data, SUCCESSFUL, status_code=200)

    def create_role(self, request):
        try:
            role_name = request.data.get("name")
            with transaction.atomic():
                serialized_data = self.serializer_class(data=request.data)
                if serialized_data.is_valid():
                    role = serialized_data.save()
                else:
                    return create_response({}, get_first_error_message_from_serializer_errors(serialized_data.errors,
                                                                                              UNSUCCESSFUL), 500)

                return create_response(self.serializer_class(role).data, message=SUCCESSFUL, status_code=200)
        except Exception as e:
            if "duplicate" in str(e).lower():
                return create_response({}, self.feature_name + " " + ALREADY_EXISTS, 500)
            return create_response({"data": e}, UNSUCCESSFUL, 500)

    def update_role(self, request):
        try:
            with transaction.atomic():
                if "id" not in request.data:
                    return create_response({}, ID_NOT_PROVIDED, 404)
                else:
                    if "name" in request.data:
                        instance = self.serializer_class.Meta.model.objects.filter(id=request.data.get("id"),
                                                                                   is_deleted=False)
                        if not instance:
                            return create_response({}, NOT_FOUND, 400)
                        instance = instance.first()
                        serialized_data = self.serializer_class(instance, data=request.data, partial=True)
                        if serialized_data.is_valid():
                            role = serialized_data.save()

                            return create_response(self.serializer_class(role).data, SUCCESSFUL, status_code=200)
                        return create_response({},
                                               get_first_error_message_from_serializer_errors(serialized_data.errors,
                                                                                              UNSUCCESSFUL),
                                               status_code=500)

                return create_response({}, UNSUCCESSFUL, status_code=500)
        except Exception as e:
            if "duplicate" in str(e).lower():
                return create_response({}, self.feature_name + " " + ALREADY_EXISTS, 500)

            return create_response({}, UNSUCCESSFUL, status_code=500)

    def delete_role(self, request):
        if "id" not in request.query_params:
            return create_response({}, ID_NOT_PROVIDED, 404)
        ids = ast.literal_eval(request.query_params.get("id"))
        with transaction.atomic():
            instances = self.serializer_class.Meta.model.objects.filter(id__in=ids,
                                                                        is_deleted=False)
            if not instances:
                return create_response({}, NOT_FOUND, 404)
            for instance in instances:
                if instance.user_role.filter(is_deleted=False).count() > 0:
                    return create_response({}, OBJECTS_ASSOCIATED_CANNOT_BE_DELETED, 500)
            instances.update(is_deleted=True, deleted_at=timezone.now())

        return create_response({}, SUCCESSFUL, 200)


class DeviceTokenController:
    serializer_class = DeviceTokenSerializerCustom

    def create(self, request):
        try:
            if "device_token" not in request.data:
                return create_response({}, UNSUCCESSFUL, 400)

            instance = self.serializer_class.Meta.model.objects.filter(user=request.user.id).first()
            if not instance:
                return create_response({}, NOT_FOUND, 404)

            serialized_requested_data = self.serializer_class(data=request.data)
            if serialized_requested_data.is_valid():
                serialized_data = self.serializer_class(instance, data=request.data, partial=True)
                if serialized_data.is_valid():
                    serialized_data.save()
                    return create_response({}, SUCCESSFUL, 200)
                else:
                    return create_response({}, get_first_error_message_from_serializer_errors(serialized_data.errors,
                                                                                              UNSUCCESSFUL),
                                           400)
            else:
                return create_response({},
                                       get_first_error_message_from_serializer_errors(serialized_requested_data.errors,
                                                                                      UNSUCCESSFUL), 400)

        except Exception as e:
            return create_response({'error': str(e)}, SOMETHING_WENT_WRONG, 500)


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
class OrganizationController:
    feature_name = "Organization Templates"
    serializer_class = OrganizationSerializer
    export_util = ExportUtility()

    def get_organization(self, request):
        kwargs = {}
        id = get_query_param(request, "id", None)
        order = get_query_param(request, "order", "desc")
        order_by = get_query_param(request, "order_by", "created_at")
        search = get_query_param(request, "search", None)
        export = get_query_param(request, 'export', None)
        if id:
            kwargs["id"] = id
        if order and order_by:
            if order == "desc":
                order_by = f"-{order_by}"

        if search:
            kwargs["name__icontains"] = search
        kwargs["is_deleted"] = False
        if request.user.role.name == 'Admin':
            user = get_query_param(request, 'admin', request.user.id)
            if user:
                kwargs["admin"] = user
            data = self.serializer_class.Meta.model.objects.filter(**kwargs).order_by(
                order_by
            )
        else:
            data = self.serializer_class.Meta.model.objects.filter(**kwargs).order_by(
                order_by
            )
        count = data.count()
        # if export:
        #     serialized_data = self.serializer_class(data, many=True)
        #     return self.export_util.export_notification_data(serialized_asset=serialized_data,
        #                                                    columns=NOTIFICATION_EXPORT_COLUMNS,
        #                                                    export_name="Organization Listing")
        data = paginate_data(data, request)
        serialized_data = self.serializer_class(data, many=True).data
        response_data = {"count": count, "data": serialized_data}
        return create_response(response_data, SUCCESSFUL, status_code=200)

    def create_organization(self, request):
        try:
            serialized_data = self.serializer_class(data=request.data)
            if serialized_data.is_valid():
                serialized_data.save()
                return create_response({},SUCCESSFUL,status_code=200)
            else:
                return create_response(
                    {},
                    get_first_error_message_from_serializer_errors(
                        serialized_data.errors, UNSUCCESSFUL
                    ),
                    status_code=500,
                )
        except Exception as e:
            if "duplicate" in str(e).lower():
                return create_response(
                    {}, self.feature_name + " " + ALREADY_EXISTS, 500
                )
            return create_response({}, UNSUCCESSFUL, 500)

    def update_organization(self, request):
        try:
            if "id" not in request.data:
                return create_response({}, ID_NOT_PROVIDED, 404)
            else:
                instance = self.serializer_class.Meta.model.objects.filter(
                    id=request.data.get("id"), is_deleted=False
                )
                if not instance:
                    return create_response({}, NOT_FOUND, 400)
                instance = instance.first()
                serialized_data = self.serializer_class(
                    instance, data=request.data, partial=True
                )
                if serialized_data.is_valid():
                    response_data = serialized_data.save()

                    return create_response(
                        self.serializer_class(response_data).data, SUCCESSFUL, 200
                    )
                return create_response(
                    {},
                    get_first_error_message_from_serializer_errors(
                        serialized_data.errors, UNSUCCESSFUL
                    ),
                    status_code=500,
                )
        except Exception as e:
            if "duplicate" in str(e).lower():
                return create_response(
                    {}, self.feature_name + " " + ALREADY_EXISTS, 500
                )
            return create_response({}, UNSUCCESSFUL, 500)

    def delete_organization(self, request):
        if "id" not in request.query_params:
            return create_response({}, ID_NOT_PROVIDED, 404)
        ids = ast.literal_eval(request.query_params.get("id"))
        instances = self.serializer_class.Meta.model.objects.filter(
            id__in=ids, is_deleted=False
        )
        if not instances:
            return create_response({}, NOT_FOUND, 404)
        instances.update(is_deleted=True, deleted_at=timezone.now())

        return create_response({}, SUCCESSFUL, 200)

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