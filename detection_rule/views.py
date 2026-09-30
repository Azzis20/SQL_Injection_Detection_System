from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render
from django.core.paginator import Paginator
from .models import DetectionRule

@login_required
def detection_rules(request):
    rules = DetectionRule.objects.all()

    per_page = request.GET.get("per_page", 5)
    paginator = Paginator(rules, per_page)
    page_number = request.GET.get("page", 1)
    page_obj = paginator.get_page(page_number)
   
    return render(request, "detection_rule/index.html", {"rules": page_obj})


# @login_required
# def attack_logs(request):
#     logs = RequestLog.objects.all()

#     per_page = request.GET.get("per_page", 5)
#     paginator = Paginator(logs, per_page)

#     page_number = request.GET.get("page", 1)
#     page_obj = paginator.get_page(page_number)

#     return render(request, "attack_logs/index.html", {"page_obj": page_obj})

