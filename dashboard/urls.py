from django.urls import path
from . import views

app_name = "dashboard"

urlpatterns = [
    path("", views.dashboard, name="index"),
    path("traffic-data/", views.traffic_data, name="traffic_data"),
]
