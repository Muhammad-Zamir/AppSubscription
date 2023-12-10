from django.core.mail import send_mail
import boto3

from utils.custom_pagination import CustomPagination
from utils.response_messages import *
from utils.reusable_methods import *
from rest_framework.pagination import LimitOffsetPagination
from utils.enums import *
from app_subscription import settings
from django.db import models
from django.contrib.auth.hashers import make_password
from user_authentication.serializers import UserListingSerializer


def send_password(first_name, last_name, email, password):
    subject = "Account Created Successfully"
    message = f"""
                Hi {first_name} {last_name},
                Your account has been created Successfully.
                Please use the following Password.
                Password: {password}
                        """
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)


def create_user(first_name, last_name, email, user_id, user_type, role):
    try:
        feature_name = "Create User"
        password = generate_dummy_password()
        user_data = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "password": make_password(password),
            "username": email,
            "employee": user_id,
            "user_type": user_type,
            "role": role
        }

        serialized_data = UserListingSerializer(data=user_data)
        if serialized_data.is_valid():
            user = serialized_data.save()
            send_password(first_name=first_name, last_name=last_name, email=email, password=password)
        else:
            print(serialized_data.errors)
            return create_response({},
                                   get_first_error_message_from_serializer_errors(serialized_data.errors, UNSUCCESSFUL),
                                   500)
    except Exception as e:
        print(e)
        return create_response({}, str(e), 500)


def user_json_helper(data, created_instance):
    employee = outlet = None
    if created_instance.__class__.__name__ == "Outlet":
        outlet = created_instance.id
        if "owner_name" in data:
            owner_name = data.get("owner_name")[0] if isinstance(data.get("owner_name"), list) else data.get(
                "owner_name")
            first_name, *last_name = (owner_name.split(" "))
            last_name = " ".join(map(str, last_name))
        else:
            first_name, *last_name = (created_instance.owner_name.split(" "))
            last_name = " ".join(map(str, last_name))
    elif created_instance.__class__.__name__ == "Employee":
        employee = created_instance.id
        first_name = data.get("first_name") if data.get("first_name") else None
        last_name = data.get("last_name") if data.get("last_name") else None
        if not first_name:
            first_name = created_instance.first_name if created_instance.first_name else ""
            last_name = created_instance.last_name if created_instance.last_name else ""
    password = generate_dummy_password()
    user_data = {
        "first_name": first_name,
        "last_name": last_name,
        "email": created_instance.email,
        "password": make_password(password),
        "username": created_instance.email,
        "employee": employee,
        "outlet": outlet,
        "user_type": "A",
        "role": data.get("role")[0] if isinstance(data.get("role"), list) else data.get("role")
    }
    return user_data, password


def paginate_data(data, request):
    limit = get_query_param(request, 'limit', None)
    offset = get_query_param(request, 'offset', None)
    if limit and offset:
        pagination = LimitOffsetPagination()
        data = pagination.paginate_queryset(data, request)
        return data
    else:
        return data

def paginate_baseapi_data(data, request):
    limit = get_query_param(request, 'limit', None)
    offset = get_query_param(request, 'offset', None)
    if limit and offset:
        pagination = CustomPagination()
        data, count = pagination.paginate_queryset(data, request)
        return data, count
    else:
        return data, data.count()


def check_for_children(instance, data, request):
    if "is_active" in request.data and data.is_active == "INACTIVE":
        change_related_objects_status(instance, param="INACTIVE")
    elif "is_active" in request.data and data.is_active == "ACTIVE":
        change_related_objects_status(instance, param="ACTIVE")
    else:
        return


def change_related_objects_status(instance, model=None, param="ACTIVE"):
    """
    Recursively deactivate all related objects of a given instance.
    """
    if model is None:
        model = instance.__class__

    for related_object in model._meta.related_objects:
        # Skip reverse relations that don't have a related name
        if not related_object.related_name:
            continue

        # Get the related manager
        related_manager = instance._meta.get_field(related_object.related_name).remote_field

        if isinstance(related_manager, models.ManyToOneRel) or isinstance(related_manager, models.OneToOneRel):
            # For ForeignKey and OneToOneField, directly get the related instance
            related_instance = getattr(instance, related_object.related_name)

            if related_instance.is_active != param:
                change_related_objects_status(related_instance, param=param)

            if hasattr(related_instance, 'is_active'):
                related_instance.is_active = param
                related_instance.save()

        elif isinstance(related_manager, models.ManyToManyRel):
            # For ManyToManyField, get the related manager through the intermediary model
            intermediary_model = related_manager.through
            related_instances = intermediary_model.objects.filter(**{
                related_manager.source_field_name: instance
            }).select_related(related_manager.target_field_name)

            for related_instance in related_instances:
                if related_instance.is_active != param:
                    change_related_objects_status(related_instance, param=param)

                if hasattr(related_instance, 'is_active'):
                    related_instance.is_active = param
                    related_instance.save()

    # Deactivate the instance itself
    if hasattr(instance, 'is_active'):
        instance.is_active = param
        instance.save()


def upload_to_s3(excel_buffer, filename):
    s3 = boto3.client('s3', aws_access_key_id=settings.AWS_S3_ACCESS_KEY_ID,
                      aws_secret_access_key=settings.AWS_S3_SECRET_ACCESS_KEY,
                      region_name=settings.AWS_S3_REGION_NAME)
    s3.upload_fileobj(excel_buffer, settings.AWS_STORAGE_BUCKET_NAME, filename)
    url = f"https://s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{settings.AWS_STORAGE_BUCKET_NAME}/{filename}"
    return url


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
