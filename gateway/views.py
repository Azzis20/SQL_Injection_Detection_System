from urllib.parse import unquote_plus
import requests
from django.http import HttpResponse
from attack_logs.models import RequestLog
from ip_management.models import BlockedIP, WhitelistedIP
from settings.models import SystemSettings
from django.views.decorators.csrf import csrf_exempt
from .detection import run_detection

TARGET_APP_URL = "http://localhost:5000"

def get_client_ip(request):
    """Prefer X-Forwarded-For when behind a tunnel/proxy, fall back to REMOTE_ADDR."""
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")

#common static file extensions
IGNORED_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", 
    ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot"
)

IGNORED_PATHS = {"favicon.ico", "traffic-data/", "traffic-data"}

@csrf_exempt
def gateway_view(request, full_path=""):

    # Check if request is for static assets or ignored paths
    if (
        full_path in IGNORED_PATHS
        or full_path.startswith("static/")
        or full_path.startswith("media/")
        or full_path.lower().endswith(IGNORED_EXTENSIONS)
    ):
        return forward_to_target(request, full_path)

    client_ip = get_client_ip(request)
    print(f"DEBUG client_ip: {repr(client_ip)}")
    print(f"DEBUG full_path: {repr(full_path)}")

    if WhitelistedIP.objects.filter(ip_address=client_ip).exists():
        return forward_to_target(request, full_path)

    if BlockedIP.objects.filter(ip_address=client_ip, is_active=True).exists():
        return HttpResponse("Blocked", status=403)

    query_params = request.GET.dict()
    body = request.body.decode(errors="ignore")
    decoded_body = unquote_plus(body)

    log = RequestLog.objects.create(
        source_ip=client_ip,
        endpoint=full_path,
        method=request.method,
        query_params=query_params,
        request_body=body,
    )

    text_to_check = decoded_body + str(query_params) 
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

    return forward_to_target(request, full_path)

def forward_to_target(request, full_path):
    target_url = f"{TARGET_APP_URL}/{full_path}"

    try:
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
            timeout=(3.0, 10.0),  # (connect timeout, read timeout)
        )
    except requests.exceptions.Timeout:
        return HttpResponse("Gateway Timeout: Upstream server timed out.", status=504)
    except requests.exceptions.RequestException:
        return HttpResponse("Bad Gateway: Unable to connect to upstream server.", status=502)

    response = HttpResponse(
        target_response.content,
        status=target_response.status_code,
        content_type=target_response.headers.get("Content-Type"),
    )

    if "Location" in target_response.headers:
        response["Location"] = target_response.headers["Location"]

    for cookie_header in target_response.raw.headers.get_all("Set-Cookie", []):
        response.headers["Set-Cookie"] = cookie_header

    return response