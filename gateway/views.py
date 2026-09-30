import requests
from django.http import HttpResponse
from attack_logs.models import RequestLog
from ip_management.models import BlockedIP, WhitelistedIP
from settings.models import SystemSettings

from .detection import run_detection

TARGET_APP_URL = "http://localhost:5000"


def gateway_view(request, full_path=""):
    client_ip = request.META.get("REMOTE_ADDR")
    print(f"DEBUG client_ip: {repr(client_ip)}")
    print(f"DEBUG full_path: {repr(full_path)}")

    # 1. Whitelisted IPs skip detection entirely and go straight through
    if WhitelistedIP.objects.filter(ip_address=client_ip).exists():
        return forward_to_target(request, full_path)

    # 2. Blocked IPs are rejected instantly, no detection needed
    if BlockedIP.objects.filter(ip_address=client_ip, is_active=True).exists():
        return HttpResponse("Blocked", status=403)

    # 3. Capture request data
    query_params = request.GET.dict()
    body = request.body.decode(errors="ignore")

    # 4. Log the request first (so RuleMatch has something to link to)
    log = RequestLog.objects.create(
        source_ip=client_ip,
        endpoint=full_path,
        method=request.method,
        query_params=query_params,
        request_body=body,
    )

    # 5. Run detection
    text_to_check = body + str(query_params)
    score = run_detection(log, text_to_check)

    if score >= 80:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 20:
        level = "medium"
    else:
        level = "low"

    settings_row = SystemSettings.objects.first()
    mode = settings_row.mode if settings_row else "blocking"
    should_block = score >= 50 and mode == "blocking"

    log.risk_score = score
    log.risk_level = level
    log.action_taken = "blocked" if should_block else "allowed"
    log.save()

    if should_block:
        return HttpResponse("Request blocked: suspicious input detected", status=403)

    # 6. Forward the clean request to the target app
    return forward_to_target(request, full_path)


def forward_to_target(request, full_path):
    target_url = f"{TARGET_APP_URL}/{full_path}"

    target_response = requests.request(
        method=request.method,
        url=target_url,
        params=request.GET.dict(),
        data=request.body,
        headers={
            k: v for k, v in request.headers.items()
            if k.lower() not in ("host", "content-length")
        },
        cookies=request.COOKIES,
        allow_redirects=False,
    )

    response = HttpResponse(
        target_response.content,
        status=target_response.status_code,
        content_type=target_response.headers.get("Content-Type"),
    )
    for cookie_header in target_response.raw.headers.get_all("Set-Cookie", []):
        response.headers["Set-Cookie"] = cookie_header

    return response