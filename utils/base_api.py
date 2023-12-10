from rest_framework.viewsets import ModelViewSet
from utils.helper import paginate_data, \
    get_first_error_message_from_serializer_errors, create_response, check_for_children, get_params, \
    paginate_baseapi_data
from utils.response_messages import *
from django.db.models import Q
from utils.enums import OperationType
from copy import deepcopy
from django.utils import timezone
from utils.base_authentication import JWTAuthentication


class BaseAPIView(ModelViewSet):
    """
        Base API View
    """
    authentication_classes = (JWTAuthentication,)
    serializer_class = None
    filter_kwargs = None
    serializers = None
    search_kwargs = {}
    extra_kwargs = {}
    select_related_args = []
    prefetch_related_args = []
    export_columns = []
    feature_name = ""
    ordering_kwargs = {}
    exclude_export_columns = None
    export_serializer = None

    def get_serializer_class(self, api_type, serializers):
        if not api_type:
            return self.serializer_class
        serializers = self.convert_to_dict(serializers)
        return serializers if not serializers else serializers[api_type]

    def convert_to_dict(self, data):
        return {key: value for key, value in data} if data else {}

    def get_filters(self, request, kwargs):
        kwargs = self.convert_to_dict(kwargs)
        filter_kwargs = {}
        for arg in request.query_params:
            if arg in kwargs.keys() and request.query_params.get(arg):
                filter_kwargs = get_params(kwargs[arg], request.query_params.get(arg), filter_kwargs)
        return filter_kwargs

    def get_search_filters(self, request, kwargs):
        filter_kwargs = {}
        if request.query_params.get("search"):
            for arg in kwargs:
                filter_kwargs[arg] = request.query_params.get("search")
        return filter_kwargs

    def get(self, request):
        try:
            self.serializer_class = self.get_serializer_class(request.query_params.get('api_type'), self.serializers)
            if not self.serializer_class:
                return create_response({}, "No serializer found", status_code=200)
            filters = self.get_filters(request, self.filter_kwargs)
            self.extra_kwargs = self.convert_to_dict(self.extra_kwargs)
            filters = dict(filters, **self.extra_kwargs)
            self.search_kwargs = self.get_search_filters(request, self.search_kwargs)
            filters["is_deleted"] = False
            if self.kwargs.get("order") and self.kwargs.get("order_by"):
                order_by = self.kwargs.get("order_by")
                if order_by in self.ordering_kwargs:
                    order_by = self.ordering_kwargs.get(order_by)
                if self.kwargs.get("order") == "desc":
                    order_by = "-" + order_by
            else:
                order_by = "-id"
            data = self.serializer_class.Meta.model.objects.select_related(*self.select_related_args).prefetch_related(
                *self.prefetch_related_args).filter(
                Q(**self.search_kwargs, _connector=Q.OR), **filters).distinct().order_by(
                order_by)

            data, count = paginate_baseapi_data(data, request)
            serialized_data = self.serializer_class(data, many=True).data
            response_data = {
                "count": count,
                "data": serialized_data
            }
            return create_response(response_data, SUCCESSFUL, status_code=200)

        except Exception as e:
            return create_response({'error': str(e)}, UNSUCCESSFUL, 500)

    def create(self, request):
        try:
            serialized_data = self.serializer_class(data=request.data)
            if serialized_data.is_valid():
                response_data = serialized_data.save()
                response_lst = [response_data.id]
                self.logs_controller.create_logs(feature=self.feature_name, object=response_lst,
                                                 operation=OperationType.CREATED,
                                                 user=request.user, model=self.serializer_class.Meta.model.__name__)
                return create_response(self.serializer_class(response_data).data, SUCCESSFUL, status_code=200)
            return create_response({},
                                   get_first_error_message_from_serializer_errors(serialized_data.errors, UNSUCCESSFUL),
                                   status_code=400)
        except Exception as e:
            if "duplicate" in str(e).lower():
                print(str(e))
                return create_response({}, self.feature_name + " " + ALREADY_EXISTS, 400)
            print(str(e))
            return create_response({str(e)}, UNSUCCESSFUL, 500)

    def update(self, request):
        try:
            if "id" not in request.data:
                return create_response({}, ID_NOT_PROVIDED, 404)
            else:
                instance = self.serializer_class.Meta.model.objects.filter(id=request.data.get("id"),
                                                                           is_deleted=False)

                if not instance:
                    return create_response({}, NOT_FOUND, 400)
                updated_fields_with_values = self.logs_controller.get_updated_fields(request.data,
                                                                                     instance.values().first())

                instance = instance.first()
                serialized_data = self.serializer_class(instance, data=request.data, partial=True)
                if serialized_data.is_valid():
                    response_data = serialized_data.save()
                    response_lst = [response_data.id]
                    check_for_children(instance, data=response_data, request=request)
                    self.logs_controller.create_logs(feature=self.feature_name, object=response_lst,
                                                     operation=OperationType.UPDATED,
                                                     user=request.user, changes=updated_fields_with_values,
                                                     model=self.serializer_class.Meta.model.__name__)
                    return create_response(self.serializer_class(response_data).data, SUCCESSFUL, 200)
                return create_response({}, get_first_error_message_from_serializer_errors(serialized_data.errors,
                                                                                          UNSUCCESSFUL),
                                       status_code=400)
        except Exception as e:
            print(e)
            if "duplicate" in str(e).lower():
                return create_response({}, self.feature_name + " " + ALREADY_EXISTS, 400)
            return create_response({str(e)}, UNSUCCESSFUL, 500)

    def delete(self, request):
        try:
            kwargs = {}
            if "id" not in request.query_params:
                return create_response({}, ID_NOT_PROVIDED, 404)
            kwargs = get_params("id", request.query_params.get("id"), kwargs)
            kwargs["is_deleted"] = False
            instances = self.serializer_class.Meta.model.objects.filter(**kwargs)
            instances_to_update = deepcopy(list(instances.values_list("id", flat=True)))
            if not instances:
                return create_response({}, NOT_FOUND, 404)
            updated_instances = instances.update(is_deleted=True, deleted_at=timezone.now())
            self.logs_controller.create_logs(feature=self.feature_name,
                                             object=instances_to_update,
                                             operation=OperationType.DELETED,
                                             user=request.user,
                                             model=self.serializer_class.Meta.model.__name__)
            return create_response({}, SUCCESSFUL, 200)

        except Exception as e:
            return create_response({'error': str(e)}, UNSUCCESSFUL, 500)
