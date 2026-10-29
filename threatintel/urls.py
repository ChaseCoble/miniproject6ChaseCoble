# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

from django.contrib.auth import views as auth_views
from django.urls import path

from threatintel import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("about/", views.about, name="about"),
    path("cve/<str:cve_id>/", views.detail, name="detail"),
    path("watchlist/", views.watchlist, name="watchlist"),
    path("watch/<str:cve_id>/add/", views.watch_add, name="watch_add"),
    path("watch/<str:cve_id>/edit/", views.watch_edit, name="watch_edit"),
    path("watch/<str:cve_id>/delete/", views.watch_delete, name="watch_delete"),
    path("refresh/", views.refresh, name="refresh"),
    path("accounts/register/", views.register, name="register"),
    path("accounts/login/", views.ThrottledLoginView.as_view(), name="login"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
]
