from django.db import models
from django.utils import timezone


class LogsMixin(models.Model):
    status_choices = (
        ("INACTIVE", "INACTIVE"),
        ("ACTIVE", "ACTIVE"),
    )
    """Add the generic fields and relevant methods common to support mostly
    models
    """
    is_deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.CharField(max_length=8, default="ACTIVE", choices=status_choices)

    def soft_delete(self, model=None):
        if hasattr(self, 'is_deleted'):
            if not self.is_deleted:
                self.is_deleted = True
                self.deleted_at = timezone.now()
                self.save()

        model = None  # Initialize model with your desired model if necessary

        if model is None:
            model = self.__class__

        for related_object in model._meta.related_objects:
            # Skip reverse relations that don't have a related name
            if not related_object.related_name:
                continue

            # Get the related manager
            related_manager = self._meta.get_field(related_object.related_name).remote_field

            if hasattr(related_manager, 'through'):
                # Skip ManyToMany relationships for now
                continue

            if isinstance(related_manager, models.ManyToOneRel) or isinstance(related_manager, models.OneToOneRel):
                # For ForeignKey and OneToOneField, directly get the related instance
                related_instance = getattr(self, related_object.related_name)

                if related_instance:
                    related_instance.soft_delete()

        # Soft delete the instance itself
        if hasattr(self, 'is_deleted'):
            if not self.is_deleted:
                self.is_deleted = True
                self.deleted_at = timezone.now()
                self.save()

    class Meta:
        """meta class for LogsMixin"""
        abstract = True
