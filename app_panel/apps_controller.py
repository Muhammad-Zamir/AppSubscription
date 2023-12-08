from django.db import transaction
from django.db.models import Prefetch
from datetime import datetime, timedelta
from utils.helper import *
from utils.base_authentication import *
from app_panel.serializers import *
import ast
from django.utils import timezone


class AppController:
    feature_name = "App Store"
    serializer_class = AppsSerializer

    def get_app(self, request):

        kwargs = {}
        id = get_query_param(request, "id", None)
        order = get_query_param(request, "order", "desc")
        order_by = get_query_param(request, "order_by", "created_at")
        search = get_query_param(request, "search", None)
        export = get_query_param(request, 'export', None)
        user=request.user.id
        if id:
            kwargs["id"] = id
        if user:
            kwargs["user"] = user
        if order and order_by:
            if order == "desc":
                order_by = f"-{order_by}"
        
        if search:
            kwargs["name__icontains"] = search
        kwargs["is_deleted"] = False
        data = self.serializer_class.Meta.model.objects.select_related('user').prefetch_related(
        Prefetch('user__user_subscriptions', queryset=Subscription.objects.select_related('plan'))
    ).filter(**kwargs).order_by(order_by)
        count = data.count()

        data = paginate_data(data, request)
        serialized_data = self.serializer_class(data, many=True).data
        response_data = {"count": count, "data": serialized_data}
        return create_response(response_data, SUCCESSFUL, status_code=200)

    from django.db import transaction

    def create_app(self, request):
        try:
            with transaction.atomic():
                request.POST._mutable = True
                request.data.update({'user': request.user.id})
                app_serializer = self.serializer_class(data=request.data)
                if app_serializer.is_valid():
                    app_instance = app_serializer.save()

                    free_plan = plan.objects.get(name='Free')
                    subscription_data = {
                        'app': app_instance.id,
                        'is_active': True,
                        'user': request.user.id,
                        'plan': free_plan.id,
                    }
                    subscription_serializer = SubscriptionSerializer(data=subscription_data)
                    if subscription_serializer.is_valid():
                        subscription_instance = subscription_serializer.save()
                        return create_response(self.serializer_class(app_instance).data, SUCCESSFUL, status_code=200)

                    app_instance.delete()
                    return create_response(
                        {},
                        get_first_error_message_from_serializer_errors(
                            subscription_serializer.errors, UNSUCCESSFUL
                        ),
                        status_code=500,
                    )

                return create_response(
                    {},
                    get_first_error_message_from_serializer_errors(
                        app_serializer.errors, UNSUCCESSFUL
                    ),
                    status_code=500,
                )

        except Exception as e:
            print(e)
            if "duplicate" in str(e).lower():
                return create_response(
                    {}, self.feature_name + " " + ALREADY_EXISTS, 500
                )
            return create_response({}, UNSUCCESSFUL, 500)

    def delete_app(self, request):
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

    def update_app(self, request):
        try:
            if "id" not in request.data:
                return create_response({}, ID_NOT_PROVIDED, 404)
            else:
                instance = self.serializer_class.Meta.model.objects.filter(id=request.data.get("id"),
                                                                           is_deleted=False)
                if not instance:
                    return create_response({}, NOT_FOUND, 400)
                instance = instance.first()
                serialized_data = self.serializer_class(instance, data=request.data, partial=True)
                if serialized_data.is_valid():
                    response_data = serialized_data.save()
                    # check_for_children(instance, data=response_data, request=request)
                    return create_response(self.serializer_class(response_data).data, SUCCESSFUL, 200)
                return create_response({}, get_first_error_message_from_serializer_errors(serialized_data.errors,
                                                                                          UNSUCCESSFUL),
                                       status_code=500)
        except Exception as e:
            return create_response({}, UNSUCCESSFUL, status_code=500)


class SubscriptionController:
    feature_name = "Subscription List"
    serializer_class = SubscriptionSerializer

    def get_subscription(self, request):
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
        data = self.serializer_class.Meta.model.objects.filter(**kwargs).order_by(
            order_by
        )
        count = data.count()

        data = paginate_data(data, request)
        serialized_data = self.serializer_class(data, many=True).data
        response_data = {"count": count, "data": serialized_data}
        return create_response(response_data, SUCCESSFUL, status_code=200)

    def create_subscription(self, request):
        try:
            serialized_data = self.serializer_class(data=request.data)
            if serialized_data.is_valid():
                response_data = serialized_data.save()

                return create_response(
                    self.serializer_class(response_data).data,
                    SUCCESSFUL,
                    status_code=200,
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

    def delete_subscription(self, request):
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

    def update_subscription(self, request):
        try:
            if "id" not in request.data:
                return create_response({}, ID_NOT_PROVIDED, 404)
            else:
                instance = self.serializer_class.Meta.model.objects.filter(id=request.data.get("id"),
                                                                           is_deleted=False)
                if not instance:
                    return create_response({}, NOT_FOUND, 400)
                instance = instance.first()
                serialized_data = self.serializer_class(instance, data=request.data, partial=True)
                if serialized_data.is_valid():
                    response_data = serialized_data.save()
                    # check_for_children(instance, data=response_data, request=request)
                    return create_response(self.serializer_class(response_data).data, SUCCESSFUL, 200)
                return create_response({}, get_first_error_message_from_serializer_errors(serialized_data.errors,
                                                                                          UNSUCCESSFUL),
                                       status_code=500)
        except Exception as e:
            return create_response({}, UNSUCCESSFUL, status_code=500)

    def cancel_subscription(self, request):
        try:
            if "id" not in request.data:
                return create_response({}, ID_NOT_PROVIDED, 404)
            else:
                instance = self.serializer_class.Meta.model.objects.filter(id=request.data.get("id"), is_deleted=False)
                if not instance:
                    return create_response({}, NOT_FOUND, 400)
                instance = instance.first()
                instance.is_active = False
                instance.save()

                return create_response(self.serializer_class(instance).data, SUCCESSFUL, 200)
        except Exception as e:
            return create_response({}, UNSUCCESSFUL, status_code=500)


class PlanController:
    feature_name = "Plan List"
    serializer_class = planSerializer

    def get_plan(self, request):
        kwargs = {}
        id = get_query_param(request, "id", None)
        order = get_query_param(request, "order", "desc")
        order_by = get_query_param(request, "order_by", "created_at")
        search = get_query_param(request, "search", None)

        if id:
            kwargs["id"] = id

        if order and order_by:
            if order == "desc":
                order_by = f"-{order_by}"

        if search:
            kwargs["name__icontains"] = search
        kwargs["is_deleted"] = False
        data = self.serializer_class.Meta.model.objects.filter(**kwargs).order_by(
            order_by
        )
        count = data.count()
        serialized_data = []

        for plan_instance in data:
            plan_data = self.serializer_class(plan_instance).data
            app_subscriptions = plan_instance.subscriptions.all()

            for subscription in app_subscriptions:
                billing_cycle_days = 30
                current_date = datetime.datetime.now().date()
                subscription_start_date = subscription.created_at.date()
                subscription_days = (current_date - subscription_start_date).days
                remaining_days = billing_cycle_days - subscription_days

                plan_data['subscription_remaining_days'] = max(0,
                                            remaining_days) if remaining_days < billing_cycle_days else subscription_days - billing_cycle_days

                serialized_data.append(plan_data)

        response_data = {"count": count, "data": serialized_data}
        return create_response(response_data, SUCCESSFUL, status_code=200)


    def create_plan(self, request):
        try:
            serialized_data = self.serializer_class(data=request.data)
            if serialized_data.is_valid():
                response_data = serialized_data.save()

                return create_response(
                    self.serializer_class(response_data).data,
                    SUCCESSFUL,
                    status_code=200,
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

    def delete_plan(self, request):
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

    def update_plan(self, request):
        try:
            if "id" not in request.data:
                return create_response({}, ID_NOT_PROVIDED, 404)
            else:
                instance = self.serializer_class.Meta.model.objects.filter(id=request.data.get("id"),
                                                                           is_deleted=False)
                if not instance:
                    return create_response({}, NOT_FOUND, 400)
                instance = instance.first()
                serialized_data = self.serializer_class(instance, data=request.data, partial=True)
                if serialized_data.is_valid():
                    response_data = serialized_data.save()
                    # check_for_children(instance, data=response_data, request=request)
                    return create_response(self.serializer_class(response_data).data, SUCCESSFUL, 200)
                return create_response({}, get_first_error_message_from_serializer_errors(serialized_data.errors,
                                                                                          UNSUCCESSFUL),
                                       status_code=500)
        except Exception as e:
            return create_response({}, UNSUCCESSFUL, status_code=500)