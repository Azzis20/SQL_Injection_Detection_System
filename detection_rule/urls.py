from django.urls import path
from . import views

app_name = "detection_rule"

urlpatterns = [
    path("", views.detection_rules, name="index"),
    path("<int:rule_id>/", views.detection_rule_detail, name="detail"),
    path("create/", views.create_detection_rule, name="create")
]
