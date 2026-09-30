from django.urls import path
from . import views

app_name = "ip_management"

urlpatterns = [

    path("", views.ip_management, name="index"),
    path("block/", views.block_ip, name="block_ip"),
    path("block/<int:pk>/", views.view_blocked_ip, name="view_blocked_ip"),
    # path("block/<int:pk>/unblock/", views.unblock_ip, name="unblock_ip"),
    path("check-ip/", views.check_ip_blocked, name="check_ip_blocked"),
]