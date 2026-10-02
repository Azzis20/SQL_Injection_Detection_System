import ipaddress
from itertools import chain
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.shortcuts import get_object_or_404, redirect, render
from .models import BlockedIP, WhitelistedIP
from django.db.models import Q
from django.views.decorators.http import require_POST





def search_ip_management(request, blocked, whitelisted):
    """Filter blocked and whitelisted IPs based on a search query."""
    query = request.GET.get("q", "").strip()

    if query:
        blocked = blocked.filter(
            Q(ip_address__icontains=query) |
            Q(reason__icontains=query)
        )

        whitelisted = whitelisted.filter(
            Q(ip_address__icontains=query)
        )

    return blocked, whitelisted, query





def _is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

@login_required
def ip_management(request):
    blocked = BlockedIP.objects.all()
    whitelisted = WhitelistedIP.objects.all()
    blocked, whitelisted, query = search_ip_management(request, blocked, whitelisted)

    combined_list = sorted(
        chain(blocked, whitelisted),
        key=lambda ip: ip.date_added,
        reverse=True
    )

    paginator = Paginator(combined_list, 10)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    return render(
        request,
        "ip_management/index.html",
        {
            "blocklist": page_obj,
            "page_obj": page_obj,
            "paginator": paginator,
            "query": query,
        }
    )

@login_required
def block_ip(request):
    """Add IP to Blocklist form (GET) + submit handler (POST)."""
    if request.method == "POST":
        ip_address = request.POST.get("ip_address", "").strip()
        reason = request.POST.get("reason", "").strip()
        confirmed = request.POST.get("confirm_block") == "on"

        error = None
        if not ip_address or not reason:
            error = "IP address and reason are required."
        elif not _is_valid_ip(ip_address):
            error = "Please enter a valid IPv4 or IPv6 address."
        elif not confirmed:
            error = "You must confirm the block action."
        elif BlockedIP.objects.filter(ip_address=ip_address, is_active=True).exists():
            error = "This IP address is already on the blocklist."

        if error:
            messages.error(request, error)
            return render(
                request,
                "ip_management/add_blocklist.html",
                {"ip_address": ip_address, "reason": reason},
            )

        BlockedIP.objects.create(
            ip_address=ip_address,
            reason=reason,
            added_by=request.user if request.user.is_authenticated else None,
        )
        messages.success(request, f"IP address {ip_address} has been blocked.")
        return redirect("ip_management:index")

    return render(request, "ip_management/add_blocklist.html", {})

@login_required
def view_blocked_ip(request, pk):
    """Read-only detail page for a blocked IP entry."""
    entry = get_object_or_404(BlockedIP, pk=pk)
    return render(request, "ip_management/view_details.html", {"entry": entry})

@login_required
def check_ip_blocked(request):
    """AJAX endpoint used by the Add-to-Blocklist form to grey out the
    submit button when the entered IP is already blocked."""
    ip_address = request.GET.get("ip", "").strip()

    if not ip_address or not _is_valid_ip(ip_address):
        return JsonResponse({"blocked": False, "valid": False})

    is_blocked = BlockedIP.objects.filter(
        ip_address=ip_address, is_active=True
    ).exists()

    return JsonResponse({"blocked": is_blocked, "valid": True})


@login_required
@require_POST
def unblock_ip(request, pk):
    """Deactivate a blocklist entry while preserving its history."""
    entry = get_object_or_404(BlockedIP, pk=pk)

    if entry.is_active:
        from django.utils import timezone

        entry.is_active = False
        entry.date_unblocked = timezone.now()
        entry.save(update_fields=["is_active", "date_unblocked"])
        messages.success(request, f"IP address {entry.ip_address} has been unblocked.")
    else:
        messages.info(request, f"IP address {entry.ip_address} is already unblocked.")

    return redirect("ip_management:view_blocked_ip", pk=entry.pk)
