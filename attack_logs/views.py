
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST
from datetime import timedelta

from ip_management.models import BlockedIP
from .models import RequestLog

DATE_RANGES = {
    "all": ("All Time", None),
    "24h": ("Last 24 Hours", timedelta(hours=24)),
    "week": ("Last 7 Days", timedelta(days=7)),
    "30days": ("Last 30 Days", timedelta(days=30)),  # matched to URL parameter
    "year": ("Last Year", timedelta(days=365)),
}

DEFAULT_RANGE = "all"

RISK_LEVELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

ACTIONS = {
    "blocked": "Blocked",
    "allowed": "Allowed",
}

ALLOWED_PER_PAGE = (5, 10)


def _url(params, **overrides):
    """Build a query string from the current GET params with some values
    replaced (or removed when the override is None). Always resets the page."""
    q = params.copy()
    q.pop("page", None)
    for key, value in overrides.items():
        if value is None:
            q.pop(key, None)
        else:
            q[key] = value
    qs = q.urlencode()
    return f"?{qs}" if qs else "?"


@login_required
def attack_logs(request):
    params = request.GET

    # --- read + validate filters ---
    range_key = params.get("range", DEFAULT_RANGE)
    if range_key not in DATE_RANGES:
        range_key = DEFAULT_RANGE

    risk = params.get("risk")
    if risk not in RISK_LEVELS:
        risk = None

    action = params.get("action")
    if action not in ACTIONS:
        action = None

    
    # search function
    query = params.get("q", "").strip()

    try:
        per_page = int(params.get("per_page", 5))
    except ValueError:
        per_page = 5
    if per_page not in ALLOWED_PER_PAGE:
        per_page = 5

    # --- apply filters ---
    logs = RequestLog.objects.all()

    delta = DATE_RANGES[range_key][1]
    if delta is not None:
        now = timezone.now()
        cutoff = now - delta
        logs = logs.filter(timestamp__gte=cutoff, timestamp__lte=now)
        
    if risk:
        logs = logs.filter(risk_level=risk)
    if action:
        logs = logs.filter(action_taken=action)

    # search function
    if query:
        logs = logs.filter(
            Q(source_ip__icontains=query)
            | Q(endpoint__icontains=query)
            | Q(method__icontains=query)
        )

    logs = logs.order_by("-timestamp")

    page_obj = Paginator(logs, per_page).get_page(params.get("page", 1))

    # --- options for the dropdowns / toggle ---
    range_options = [
        {"label": label, "url": _url(params, range=key), "active": key == range_key}
        for key, (label, _) in DATE_RANGES.items()
    ]

    risk_options = [
        {"label": "All Risks", "url": _url(params, risk=None), "active": risk is None}
    ] + [
        {"label": label, "url": _url(params, risk=key), "active": key == risk}
        for key, label in RISK_LEVELS.items()
    ]

    # Clicking the active toggle again clears the filter (shows both).
    action_options = [
        {
            "label": label,
            "url": _url(params, action=None if key == action else key),
            "active": key == action,
        }
        for key, label in ACTIONS.items()
    ]

    # Query string without "page", used by the pagination links.
    base_qs = params.copy()
    base_qs.pop("page", None)

    return render(request, "attack_logs/index.html", {
        "page_obj": page_obj,
        "query": query,
        "range_key": range_key,
        "risk": risk,
        "action": action,
        "per_page": per_page,
        "range_label": DATE_RANGES[range_key][0],
        "risk_label": RISK_LEVELS.get(risk, "All Risks"),
        "range_options": range_options,
        "risk_options": risk_options,
        "action_options": action_options,
        "base_qs": base_qs.urlencode(),
    })


@login_required
def attack_log_detail(request, log_id):
    log = get_object_or_404(RequestLog, id=log_id)
    is_source_ip_blocked = BlockedIP.objects.filter(
        ip_address=log.source_ip,
        is_active=True,
    ).exists()
    return render(
        request,
        "attack_logs/view.html",
        {"log": log, "is_source_ip_blocked": is_source_ip_blocked},
    )


@login_required
@require_POST
def block_log_source_ip(request, log_id):
    """Block the source IP recorded for an attack log."""
    log = get_object_or_404(RequestLog, id=log_id)
    existing_entry = BlockedIP.objects.filter(ip_address=log.source_ip).first()

    if existing_entry and existing_entry.is_active:
        messages.info(request, f"IP address {log.source_ip} is already blocked.")
    else:
        BlockedIP.objects.update_or_create(
            ip_address=log.source_ip,
            defaults={
                "reason": f"Blocked from attack log #{log.pk} ({log.risk_level} risk)",
                "added_by": request.user,
                "is_active": True,
                "date_added": timezone.now(),
                "date_unblocked": None,
            },
        )
        messages.success(request, f"IP address {log.source_ip} has been blocked.")

    return redirect("attack_logs:detail", log_id=log.pk)
