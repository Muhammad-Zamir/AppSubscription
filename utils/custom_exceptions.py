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

# def custom_exception_handler(exc, context):
#     """Call REST framework's default exception handler to set a standard error response on error."""
#     # logger.info("inside of custom exception handler.")
#
#     response = exception_handler(exc, context)
#     logger.error(f" {colored('context', 'yellow')}: {context}")
#     logger.error(f" {colored('exception', 'yellow')}: {exc}")
#     logger.error(f" {colored('response', 'yellow')}: {response}")
#
#     # The exception handler function should either return a Response object,or None
#     # If the handler returns None then the exception will be re-raised and
#     # Django will return a standard HTTP 500 'server error' response.
#     # so override the response None and return standard response with HTTP_400_BAD_REQUEST
#     if response is None:
#         return Response(
#             data={
#                 "data": {},
#                 "meta": {
#                     "status_code": status.HTTP_400_BAD_REQUEST,
#                     "message": "Something went wrong during process.Try again later.",
#                 }
#             },
#             status=status.HTTP_400_BAD_REQUEST,
#         )
#     return Response(
#         data={
#             "data": {},
#             "meta": {
#                 "status_code": status.HTTP_400_BAD_REQUEST,
#                 "message": f"{exc}",
#             }
#         },
#         status=response.status_code
#     )
