from django.db import models


class SystemSettings(models.Model):
    """Holds gateway-level configuration, including the target Laravel app
    URL and monitoring/blocking mode."""

    target_app_url = models.URLField(
        help_text="Base URL of the target app, e.g. http://localhost:5000"
    )
    mode = models.CharField(
        max_length=20,
        choices=[("monitoring", "Monitoring only"), ("blocking", "Detect and block")],
        default="blocking",
    )
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "System settings"