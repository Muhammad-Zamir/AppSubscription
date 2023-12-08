from django.urls import path
from .views import *

urlpatterns = [
    path('app', AppView.as_view(
        {"get": "get_records", "post": "create_record",
         "patch": "update_record", "delete": "delete_records"
         }
    )
         ),
    path('subscription', SubscriptionView.as_view(
        {"get": "get_records", "post": "create_record",
         "patch": "update_record", "delete": "delete_records"
         }
    )
         ),
    path('cancel_subscription', SubscriptionView.as_view(
        {
         "patch": "cancel_subscription"
         }
    )
         ),
    path('plan', PlanView.as_view(
        {"get": "get_records", "post": "create_record",
         "patch": "update_record", "delete": "delete_records"
         }
    )
         ),
]