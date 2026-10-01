import re

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse

from .models import DetectionRule, RuleMatch

ALLOWED_PER_PAGE = (5, 10)
DEFAULT_PER_PAGE = 5
RECENT_MATCHES = 10


@login_required
def detection_rules(request):
    rules = DetectionRule.objects.all()

    try:
        per_page = int(request.GET.get("per_page", DEFAULT_PER_PAGE))
    except (ValueError, TypeError):
        per_page = DEFAULT_PER_PAGE

    if per_page not in ALLOWED_PER_PAGE:
        per_page = DEFAULT_PER_PAGE

    paginator = Paginator(rules, per_page)
    page_number = request.GET.get("page", 1)
    page_obj = paginator.get_page(page_number)

    return render(request, "detection_rule/index.html", {"rules": page_obj})


@login_required
def detection_rule_detail(request, rule_id):
    rule = get_object_or_404(DetectionRule, id=rule_id)
    matches = RuleMatch.objects.filter(rule=rule).order_by("-id")[:RECENT_MATCHES]

    return render(request, "detection_rule/detection_detail.html", {
        "rule": rule,
        "matches": matches,
        "match_count": rule.matches.count(),
        "just_created": request.GET.get("created") == "1",
    })


def _validate_rule_form(data):
    """Returns (cleaned_values, errors)."""
    errors = []
    valid_types = {value for value, _ in DetectionRule.RULE_TYPE_CHOICES}

    name = data.get("name", "").strip()
    rule_type = data.get("rule_type", "")
    pattern = data.get("pattern", "").strip()
    category = data.get("category", "").strip()

    if not name:
        errors.append("Rule name is required.")
    elif len(name) > 150:
        errors.append("Rule name must be 150 characters or fewer.")

    if rule_type not in valid_types:
        errors.append("Choose a valid rule type.")

    if len(category) > 100:
        errors.append("Category must be 100 characters or fewer.")

    if not pattern:
        errors.append("Pattern is required.")
    elif rule_type in ("signature", "anomaly"):
        try:
            re.compile(pattern)
        except re.error as exc:
            errors.append(f"Pattern is not valid regex: {exc}")

    try:
        risk_weight = int(data.get("risk_weight", 10))
        if not 1 <= risk_weight <= 100:
            raise ValueError
    except (ValueError, TypeError):
        errors.append("Risk weight must be a whole number between 1 and 100.")
        risk_weight = 10

    values = {
        "name": name,
        "rule_type": rule_type,
        "pattern": pattern,
        "category": category,
        "risk_weight": risk_weight,
        "is_enabled": data.get("is_enabled") == "on",
    }
    return values, errors


@login_required
def create_detection_rule(request):
    context = {
        "rule_types": DetectionRule.RULE_TYPE_CHOICES,
        "values": {"rule_type": "signature", "risk_weight": 10, "is_enabled": True},
        "errors": [],
    }

    if request.method == "POST":
        values, errors = _validate_rule_form(request.POST)
        if errors:
            context.update(values=values, errors=errors)
            return render(request, "detection_rule/add_rule.html", context)

        new_rule = DetectionRule.objects.create(**values)
        # Redirect (Post/Redirect/Get) so a refresh doesn't resubmit the form
        return redirect(f"{reverse('detection_rule:detail', args=[new_rule.id])}?created=1")

    return render(request, "detection_rule/add_rule.html", context)