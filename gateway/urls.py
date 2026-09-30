from django.urls import re_path
from .views import gateway_view

urlpatterns = [
    re_path(r'^(?P<full_path>.*)$', gateway_view),
]