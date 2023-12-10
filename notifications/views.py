from notifications.serializers import NotificationFeaturesSerializer, EmailTemplateSerializer
from utils.base_api import *
# Create your views here.
class NotificationFeaturesListingView(BaseAPIView):
    serializer_class = NotificationFeaturesSerializer
    feature_name = "Notification Feature"

    search_kwargs = ["name__icontains"]

class EmailTempleteListingView(BaseAPIView):

    serializer_class = EmailTemplateSerializer
    feature_name = "Email Feature"

    search_kwargs = ["name__icontains"]