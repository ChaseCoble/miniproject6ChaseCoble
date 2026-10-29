# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods, require_POST

from threatintel import services, throttle
from threatintel.fetch import FetchError
from threatintel.forms import WatchNoteForm
from threatintel.models import Vulnerability, Watch
from threatintel.nvd_cache import nvd_is_stale
from threatintel.sources import parse_kev, parse_nvd, validate_cve_id

LOGIN_LIMIT, LOGIN_WINDOW = 5, timedelta(minutes=15)
REGISTER_LIMIT, REGISTER_WINDOW = 5, timedelta(hours=1)
NVD_LIMIT, NVD_WINDOW = 5, timedelta(seconds=30)
REFRESH_LIMIT, REFRESH_WINDOW = 1, timedelta(hours=1)
PAGE_SIZE = 100
# App-wide throttles share one key
GLOBAL = ""


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


def dashboard(request):
    q = request.GET.get("q", "").strip()
    # cve_id breaks date ties so rows never shift between pages
    rows = Vulnerability.objects.order_by("-date_added", "cve_id")
    if q:
        # icontains escapes % and _, so they match literally
        rows = rows.filter(Q(cve_id__icontains=q) | Q(vendor__icontains=q) | Q(product__icontains=q))
    # get_page never raises: bad values give page 1, out-of-range the last page
    page = Paginator(rows, PAGE_SIZE).get_page(request.GET.get("page"))
    return render(request, "dashboard.html", {"page": page, "q": q})


def about(request):
    return render(request, "about.html")


def fetch_nvd_for(vuln):
    # True if fresh NVD data was saved; False means "unavailable", nothing saved
    if throttle.is_limited("nvd", GLOBAL, NVD_LIMIT, NVD_WINDOW, services.now()):
        return False
    # Every attempt counts, so a failing NVD isn't hammered either
    throttle.record("nvd", GLOBAL, services.now())
    try:
        result = parse_nvd(services.fetch_nvd(vuln.cve_id))
    except (FetchError, ValueError):
        return False
    if result is None:
        return False
    services.save_nvd(result, services.now())
    return True


def detail(request, cve_id):
    # Validate before any lookup or fetch
    if not validate_cve_id(cve_id):
        raise Http404
    vuln = get_object_or_404(Vulnerability, cve_id=cve_id)
    nvd_unavailable = False
    # Anonymous visitors only ever see what is already cached
    if request.user.is_authenticated and nvd_is_stale(vuln.nvd_status, vuln.nvd_fetched_at, services.now()):
        if fetch_nvd_for(vuln):
            vuln.refresh_from_db()
        else:
            nvd_unavailable = True
    return render(request, "detail.html", {"vuln": vuln, "nvd_unavailable": nvd_unavailable})


@never_cache
@login_required
def watchlist(request):
    watches = Watch.objects.filter(user=request.user).select_related("vulnerability").order_by("-created")
    return render(request, "watchlist.html", {"watches": watches})


@login_required
@require_POST
def watch_add(request, cve_id):
    if not validate_cve_id(cve_id):
        raise Http404
    vuln = get_object_or_404(Vulnerability, cve_id=cve_id)
    _, created = Watch.objects.get_or_create(user=request.user, vulnerability=vuln)
    if not created:
        messages.info(request, f"You are already watching {vuln.cve_id}.")
    return redirect("watchlist")


@never_cache
@login_required
@require_http_methods(["GET", "POST"])
def watch_edit(request, cve_id):
    # Scoped to request.user: someone else's watch is a plain 404
    watch = get_object_or_404(Watch, user=request.user, vulnerability__cve_id=cve_id)
    if request.method == "POST":
        form = WatchNoteForm(request.POST, instance=watch)
        if form.is_valid():
            form.save()
            return redirect("watchlist")
    else:
        form = WatchNoteForm(instance=watch)
    return render(request, "watch_edit.html", {"form": form, "watch": watch})


@login_required
@require_POST
def watch_delete(request, cve_id):
    # Deletes the watch only, never the vulnerability
    get_object_or_404(Watch, user=request.user, vulnerability__cve_id=cve_id).delete()
    return redirect("watchlist")


@login_required
@require_POST
def refresh(request):
    if throttle.is_limited("refresh", GLOBAL, REFRESH_LIMIT, REFRESH_WINDOW, services.now()):
        return too_many(request)
    try:
        rows = parse_kev(services.fetch_kev())
    except (FetchError, ValueError):
        messages.error(request, "The KEV feed is unavailable right now. Nothing was changed.")
        return redirect("dashboard")
    services.upsert_kev(rows)
    # Recorded only after a successful load, so a failure doesn't start the window
    throttle.record("refresh", GLOBAL, services.now())
    messages.success(request, f"Loaded {len(rows)} KEV entries.")
    return redirect("dashboard")
