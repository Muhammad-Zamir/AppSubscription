from utils.helper import *
from utils.base_authentication import *
from notifications.serializers import *
import ast
from django.utils import timezone


class EmailTemplateController:
    feature_name = "Email Templates"
    serializer_class = EmailTemplateSerializer

    def get_email_templete(self, request):
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

    def create_email_templete(self, request):
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

    def update_email_templete(self, request):
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

    def delete_email_templete(self, request):
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


class NotificationFeaturesController:
    feature_name = "Notification Features"
    serializer_class = NotificationFeaturesSerializer

    def get_notification_features(self, request):
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

    def create_notification_features(self, request):
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

    def delete_notification_features(self, request):
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

    def update_notification_features(self, request):
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
