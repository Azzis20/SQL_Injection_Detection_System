from django.urls import path
from . import views

app_name = "detection_rule"

urlpatterns = [
    path("", views.detection_rules, name="index"),
]
