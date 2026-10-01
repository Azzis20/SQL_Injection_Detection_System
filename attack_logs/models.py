from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


# Create your models here.

class RequestLog(models.Model):
    """Records every inspected request - its data, risk score, and whether
    it was allowed or blocked."""

    METHOD_CHOICES = [
        ("GET", "GET"),
        ("POST", "POST"),
        ("PUT", "PUT"),
        ("DELETE", "DELETE"),
        ("PATCH", "PATCH"),
    ]

    RISK_LEVEL_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    ACTION_CHOICES = [
        ("allowed", "Allowed"),
        ("blocked", "Blocked"),
    ]

    # timestamp = models.DateTimeField(auto_now_add=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    source_ip = models.GenericIPAddressField()
    endpoint = models.CharField(max_length=255)
    method = models.CharField(max_length=10, choices=METHOD_CHOICES)
    user_agent = models.TextField(blank=True)

    # captured input, stored as raw text/JSON for forensic review
    query_params = models.JSONField(blank=True, null=True)
    request_body = models.TextField(blank=True, null=True)
    headers = models.JSONField(blank=True, null=True)
    cookies = models.JSONField(blank=True, null=True)

    payload_snippet = models.TextField(blank=True, help_text="The specific matched/suspicious input")
    risk_score = models.PositiveIntegerField(default=0)
    risk_level = models.CharField(max_length=10, choices=RISK_LEVEL_CHOICES, default="low")
    action_taken = models.CharField(max_length=10, choices=ACTION_CHOICES, default="allowed")

    is_false_positive = models.BooleanField(default=False)
    reviewed_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name="reviewed_logs"
    )

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["source_ip"]),
            models.Index(fields=["endpoint"]),
            models.Index(fields=["risk_level"]),
            models.Index(fields=["timestamp"]),
        ]

    def __str__(self):
        return f"{self.timestamp} | {self.source_ip} | {self.endpoint} | {self.risk_level}"

# Create your models here.
