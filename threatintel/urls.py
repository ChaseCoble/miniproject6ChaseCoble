# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

from django.contrib.auth import views as auth_views
from django.urls import path

from threatintel import views

urlpatterns = [
    path("watchlist/", views.watchlist, name="watchlist"),
    path("accounts/register/", views.register, name="register"),
    path("accounts/login/", views.ThrottledLoginView.as_view(), name="login"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
]
