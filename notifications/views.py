from rest_framework import viewsets
from notifications.notification_controller import EmailTemplateController, NotificationFeaturesController
from user_authentication.permission import IsSuperAdmin
from utils.base_authentication import JWTAuthentication
from notifications.serializers import *

email_templete_controller = EmailTemplateController()
notification_feature_controller = NotificationFeaturesController()


class EmailTempleteListingView(viewsets.ModelViewSet):
    """
    Endpoints for department CRUDs.
    """

    authentication_classes = (JWTAuthentication,)
    serializer_class = EmailTemplateSerializer
    permission_classes = [IsSuperAdmin]

    def get(self, request):
        return email_templete_controller.get_email_templete(request)

    def create(self, request):
        return email_templete_controller.create_email_templete(request)

    def update(self, request):
        return email_templete_controller.update_email_templete(request)

    def destroy(self, request):
        return email_templete_controller.delete_email_templete(request)


class NotificationFeaturesListingView(viewsets.ModelViewSet):
    """
    Endpoints for department CRUDs.
    """

    authentication_classes = (JWTAuthentication,)
    serializer_class = NotificationFeaturesSerializer
    permission_classes = [IsSuperAdmin]

    def get(self, request):
        return notification_feature_controller.get_notification_features(request)

    def create(self, request):
        return notification_feature_controller.create_notification_features(request)

    def update(self, request):
        return notification_feature_controller.update_notification_features(request)

    def destroy(self, request):
        return notification_feature_controller.delete_notification_features(request)
