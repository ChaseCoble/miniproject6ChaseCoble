# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

from datetime import timedelta

from django.conf import settings
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods

from threatintel import services, throttle

LOGIN_LIMIT, LOGIN_WINDOW = 5, timedelta(minutes=15)
REGISTER_LIMIT, REGISTER_WINDOW = 5, timedelta(hours=1)


def too_many(request):
    return render(request, "too_many.html", status=429)


def login_throttle_key(request):
    # Normalized so "Alice " and "alice" share one bucket; unknown usernames count too
    return request.POST.get("username", "").strip().lower()


class ThrottledLoginView(auth_views.LoginView):
    # Django's LoginView, with failures counted per username
    def post(self, request, *args, **kwargs):
        key = login_throttle_key(request)
        if throttle.is_limited("login", key, LOGIN_LIMIT, LOGIN_WINDOW, services.now()):
            # Blocked attempts are not recorded, so the window can't be extended
            return too_many(request)
        return super().post(request, *args, **kwargs)

    def form_invalid(self, form):
        throttle.record("login", login_throttle_key(self.request), services.now())
        return super().form_invalid(form)


@require_http_methods(["GET", "POST"])
def register(request):
    if request.method == "POST":
        # REMOTE_ADDR only; X-Forwarded-For is client-controlled
        address = request.META.get("REMOTE_ADDR", "")
        if throttle.is_limited("register", address, REGISTER_LIMIT, REGISTER_WINDOW, services.now()):
            return too_many(request)
        throttle.record("register", address, services.now())
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()  # not logged in: the user signs in on the next page
            return redirect(settings.LOGIN_URL)
    else:
        form = UserCreationForm()
    return render(request, "registration/register.html", {"form": form})


@never_cache
@login_required
def watchlist(request):
    return render(request, "watchlist.html")
