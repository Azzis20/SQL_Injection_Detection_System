from django.urls import path
from . import views

app_name = "attack_logs"

urlpatterns = [
    path("", views.attack_logs, name="index"),
    path("<int:log_id>/", views.attack_log_detail, name="detail"),
    path("<int:log_id>/block-ip/", views.block_log_source_ip, name="block_source_ip"),
    # path("search/", views.search_attack_logs, name="search"),
]


