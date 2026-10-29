# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

from django.contrib import admin

from threatintel.models import Vulnerability, Watch

NVD_FIELDS = (
    "nvd_status", "nvd_published", "nvd_last_modified", "cvss_score", "cvss_version",
    "cvss_severity", "cvss_vector", "cvss_source", "cvss_type", "nvd_fetched_at",
)


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("cve_id", "vendor", "product", "date_added", "due_date", "ransomware_use", "cvss_score")
    search_fields = ("cve_id", "vendor", "product")
    list_filter = ("ransomware_use", "cvss_severity")
    ordering = ("-date_added", "cve_id")
    # NVD data only ever comes from save_nvd, never from a form
    readonly_fields = NVD_FIELDS
    fieldsets = (
        ("KEV", {"fields": ("cve_id", "vendor", "product", "name", "short_description",
                            "date_added", "due_date", "ransomware_use", "cwes", "kev_urls")}),
        ("NVD (read-only)", {"fields": NVD_FIELDS}),
    )


@admin.register(Watch)
class WatchAdmin(admin.ModelAdmin):
    list_display = ("user", "vulnerability", "created")
    # Search boxes instead of dropdowns, which would list the whole catalogue
    raw_id_fields = ("user", "vulnerability")
