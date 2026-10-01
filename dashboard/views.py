from datetime import timedelta
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q, Sum
from django.shortcuts import render
from django.utils import timezone
from attack_logs.models import RequestLog
from detection_rule.models import DetectionRule


@login_required
def traffic_data(request):
    """
    Returns request/blocked counts bucketed into 15-min intervals
    for the last hour.
    """
    now = timezone.now()
    bucket_minutes = 15
    num_buckets = 5

    start = now - timedelta(minutes=bucket_minutes * (num_buckets - 1))
    start = start.replace(
        minute=(start.minute // bucket_minutes) * bucket_minutes,
        second=0,
        microsecond=0,
    )

    labels, total_requests, blocked_threats = [], [], []

    for i in range(num_buckets):
        b_start = start + timedelta(minutes=bucket_minutes * i)
        b_end = b_start + timedelta(minutes=bucket_minutes)

        local_label_time = timezone.localtime(b_start)
        label = local_label_time.strftime("%H:%M")
        if i == num_buckets - 1:
            label += " (Now)"
        labels.append(label)

        counts = RequestLog.objects.filter(
            timestamp__gte=b_start,
            timestamp__lt=b_end,
        ).aggregate(
            total=Count("id"),
            blocked=Count("id", filter=Q(action_taken="blocked"))
        )

        total_requests.append(counts["total"] or 0)
        blocked_threats.append(counts["blocked"] or 0)

    return JsonResponse(
        {
            "labels": labels,
            "total_requests": total_requests,
            "blocked_threats": blocked_threats,
        }
    )


def format_count(n):
    if n >= 1000:
        return f"{n / 1000:.1f}k"
    return str(n)


@login_required
def dashboard(request):
    logs = RequestLog.objects.order_by("-timestamp")[:7]

    #detection rules count which is active  
    
    # rules_active = DetectionRule.objects.aggregate(
    #     total=Sum("is_enabled")
    # )["total"] or 0
    rules_active = DetectionRule.objects.filter(is_enabled=True).count()


    # Threat Distribution
    level_counts = RequestLog.objects.values("risk_level").annotate(count=Count("id"))
    counts = {row["risk_level"]: row["count"] for row in level_counts}
    total = sum(counts.values())

    def pct(level):
        return round(counts.get(level, 0) / total * 100) if total else 0

    threat_distribution = {
        "critical": pct("critical"),
        "high": pct("high"),
        "medium": pct("medium"),
        "low": pct("low"),
    }

    # --- Timezone-aware local day boundaries ---
    now = timezone.localtime(timezone.now())
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    yesterday_start = today_start - timedelta(days=1)

    # Use explicit datetime ranges instead of timestamp__date
    requests_today = RequestLog.objects.filter(
        timestamp__gte=today_start, timestamp__lt=today_end
    ).count()

    requests_yesterday = RequestLog.objects.filter(
        timestamp__gte=yesterday_start, timestamp__lt=today_start
    ).count()

    change_pct = (
        round((requests_today - requests_yesterday) / requests_yesterday * 100, 1)
        if requests_yesterday > 0 else 0
    )

    # Combined query for blocked counts today
    today_blocked_stats = RequestLog.objects.filter(
        timestamp__gte=today_start,
        timestamp__lt=today_end,
        action_taken="blocked"
    ).aggregate(
        total_blocked=Count("id"),
        high_risk_blocked=Count("id", filter=Q(risk_level__in=["high", "critical"]))
    )

    blocked_today = today_blocked_stats["total_blocked"]
    high_risk_detected = today_blocked_stats["high_risk_blocked"] > 0

    

    context = {
        "logs": logs,
        "threat_distribution": threat_distribution,
        "total_threats": format_count(total),
        "total_requests": format_count(requests_today),
        "requests_change_pct": change_pct,
        "blocked_attempts": format_count(blocked_today),
        "high_risk_detected": high_risk_detected,
        "rules_active": rules_active,
    }
    return render(request, "dashboard/dashboard.html", context)