from django.test import TestCase, RequestFactory
from unittest.mock import patch
from app_panel.apps_controller import AppController
from app_panel.serializers import AppsSerializer
from app_panel.models import App
from user_authentication.models import User
from django.urls import reverse

class AppControllerTestCase(TestCase):

    def setUp(self):
        self.factory = RequestFactory()

    @patch('app_panel.apps_controller.get_query_param')
    def test_get_app(self, mock_get_query_param):
        mock_get_query_param.side_effect = lambda req, param, default: {
            'id': 1,
            'order': 'desc',
            'order_by': 'created_at',
            'search': 'Test App',
            'export': None,
        }.get(param, default)

        # Create a user and associate it with the request
        user = User.objects.create(username='test_user')
        request = self.factory.get('/app', {'id': '15', 'search': 'Test App'})
        request.user = user
        query_params = request.GET
        app_controller = AppController()
        app_controller.serializer_class = AppsSerializer
        app_controller.get_app(request)

        mock_get_query_param.assert_called_with(request, 'id', None)
        self.assertEqual(app_controller.serializer_class.Meta.model.objects.filter.call_count, 1)
        self.assertEqual(app_controller.serializer_class.Meta.model.objects.filter().count.call_count, 1)

