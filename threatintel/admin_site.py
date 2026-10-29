# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

from django.contrib import admin
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.translation import gettext as _


class ThrottledAdminSite(admin.AdminSite):
    def login(self, request, extra_context=None):
        # Same as Django's AdminSite.login, except it runs ThrottledLoginView,
        # so the admin login shares the site's "login" throttle bucket.
        # Imported here, as Django does, because this module loads with the admin app.
        from django.contrib.admin.forms import AdminAuthenticationForm

        from threatintel.views import ThrottledLoginView

        redirect_url = ThrottledLoginView().get_redirect_url(request) or reverse(
            "admin:index", current_app=self.name
        )
        if request.method == "GET" and self.has_permission(request):
            # Already logged in as staff
            return HttpResponseRedirect(redirect_url)

        context = {
            **self.each_context(request),
            "title": _("Log in"),
            "subtitle": None,
            "app_path": request.get_full_path(),
            "username": request.user.get_username(),
            REDIRECT_FIELD_NAME: redirect_url,
        }
        context.update(extra_context or {})

        request.current_app = self.name
        return ThrottledLoginView.as_view(
            extra_context=context,
            authentication_form=self.login_form or AdminAuthenticationForm,
            template_name=self.login_template or "admin/login.html",
        )(request)
