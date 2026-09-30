
from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class BlockedIP(models.Model):
    """Tracks IP addresses currently prevented from reaching the target
    application."""


    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=255) 
    attempt_count = models.PositiveIntegerField(default=1)
    is_active = models.BooleanField(default=True)
    added_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    date_added = models.DateTimeField(auto_now_add=True)
    date_unblocked = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.ip_address


class WhitelistedIP(models.Model):
    # Tracks trusted IP addresses that bypass detection entirely
    # (e.g. internal QA)

    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=255, blank=True)
    added_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    date_added = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address