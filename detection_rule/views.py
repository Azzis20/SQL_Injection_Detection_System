from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import render
from .models import DetectionRule

ALLOWED_PER_PAGE = (5, 10)
DEFAULT_PER_PAGE = 5

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