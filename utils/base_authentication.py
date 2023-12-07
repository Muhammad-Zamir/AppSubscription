from rest_framework import exceptions
from user_authentication.models import Token
from utils.reusable_methods import *
from rest_framework.authentication import BaseAuthentication
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import get_user_model
from utils.custom_exceptions import *
import jwt

class AuthenticationBackend(object):
    def authenticate(self, request, username=None, password=None, **kwargs):
        User = get_user_model()
        try:
            user = User.objects.get(email__iexact=username, is_deleted=False)
        except User.DoesNotExist:
            return None
        else:
            if getattr(user, 'is_active', "INACTIVE") and user.check_password(password):
                return user
        return None

    def get_user(self, user_id):
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


class JWTAuthentication(BaseAuthentication):
    """
        custom authentication class for DRF and JWT
        https://github.com/encode/django-rest-framework/blob/master/rest_framework/authentication.py
    """

    @csrf_exempt
    def authenticate(self, request):
        authorization_header = request.headers.get('Authorization')
        if not authorization_header:
            raise exceptions.AuthenticationFailed('Token not provided')
        try:
            access_token = authorization_header.split(' ')[1]
            if not Token.objects.filter(token=access_token, is_active="ACTIVE").exists():
                raise SessionExpired()
            access_token = decrypt_token(access_token)
            payload = jwt.decode(access_token, settings.JWT_ENCODING_SECRET_KEY, algorithms=['HS256'])
        except IndexError:
            raise exceptions.AuthenticationFailed('Token prefix missing')
        except jwt.ExpiredSignatureError:
            raise SessionExpired()
        except jwt.InvalidTokenError:
            raise exceptions.NotAcceptable('Invalid token')

        from user_authentication.models import User
        user = User.objects.filter(email=payload['email'], is_deleted=False).first()
        if user is None or not user.is_active:
            raise exceptions.AuthenticationFailed('Invalid User.')
        return user, None
