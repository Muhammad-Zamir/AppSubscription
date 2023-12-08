from rest_framework import permissions

class IsSuperAdmin(permissions.BasePermission):
    """
    Custom permission to allow only Super Admin users.
    """
    def has_permission(self, request, view):
        if request.user.is_superuser:
            return request.user.is_authenticated
        else:
            return request.user.is_authenticated and request.user.role.name == 'Super Admin'
class IsAdmin(permissions.BasePermission):
    """
    Custom permission to allow only Super Admin users.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_superuser