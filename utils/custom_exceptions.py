from rest_framework.exceptions import APIException
from rest_framework import status


class FeatureIdRequired(APIException):
    status_code = status.HTTP_406_NOT_ACCEPTABLE
    default_detail = {'data': {}, 'message': 'Feature ID not provided'}
    default_code = 'not_authenticated'


class NotAuthorized(APIException):
    status_code = status.HTTP_406_NOT_ACCEPTABLE
    default_detail = {'data': {}, 'message': 'You are not authorized to perform this action'}
    default_code = 'not_authenticated'


class PasswordAlreadyUsed(APIException):
    status_code = status.HTTP_406_NOT_ACCEPTABLE
    default_detail = {'data': {}, 'message': 'This password has already been used in the last 6 passwords.'}
    default_code = 'not_authenticated'


class PasswordMustBeEightChar(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = {'data': {}, 'message': 'Password must be at least 8 characters long.'}
    default_code = 'not_authenticated'


class SameOldPassword(APIException):
    status_code = status.HTTP_406_NOT_ACCEPTABLE
    default_detail = {'data': {}, 'message': 'New password cannot be same as old password'}
    default_code = 'not_authenticated'


class SessionExpired(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = {'data': {}, 'message': 'Session Expired'}
    default_code = 'not_authenticated'


