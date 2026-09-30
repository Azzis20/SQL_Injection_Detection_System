from django.db import models


class DetectionRule(models.Model):
    """Stores the configurable signature, anomaly, and keyword rules the
    detection engine checks every request against."""

    RULE_TYPE_CHOICES = [
        ("signature", "Signature"),
        ("anomaly", "Anomaly"),
        ("keyword", "Keyword"),
    ]

    name = models.CharField(max_length=150)
    rule_type = models.CharField(max_length=20, choices=RULE_TYPE_CHOICES)
    pattern = models.TextField(help_text="Regex or keyword pattern to match against input")
    category = models.CharField(max_length=100, blank=True, help_text="e.g. Union-based, Boolean-based, Time-based")
    risk_weight = models.PositiveIntegerField(default=10, help_text="Points added to risk score when triggered")
    is_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class RuleMatch(models.Model):
    """Links a specific request log to the rule(s) that triggered on it,
    showing exactly what matched and how many points it added."""

    request_log = models.ForeignKey(
        "attack_logs.RequestLog", on_delete=models.CASCADE, related_name="rule_matches"
    )
    rule = models.ForeignKey(DetectionRule, on_delete=models.CASCADE, related_name="matches")
    matched_value = models.TextField(help_text="The exact substring/value that matched the rule")
    points_awarded = models.PositiveIntegerField(default=0)

    def __str__(self):
        return f"{self.rule.name} -> {self.request_log_id}"