from django.urls import path
from . import views

app_name = "attack_logs"

urlpatterns = [
    path("", views.attack_logs, name="index"),
    path("<int:log_id>/", views.attack_log_detail, name="detail"),
    # path("search/", views.search_attack_logs, name="search"),
]


