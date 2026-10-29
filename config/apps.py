# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

from django.contrib.admin.apps import AdminConfig


class ThrottledAdminConfig(AdminConfig):
    # Replaces django.contrib.admin in INSTALLED_APPS so admin.site is our subclass
    default_site = "threatintel.admin_site.ThrottledAdminSite"
