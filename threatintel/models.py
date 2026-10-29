# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from threatintel.sources import validate_cve_id


def validate_cve_id_field(value):
    # Reuses the parser's fullmatch, so a trailing "\n" is rejected here too
    if not validate_cve_id(value):
        raise ValidationError("Enter a CVE ID like CVE-2021-44228.")


class Vulnerability(models.Model):
    # KEV fields
    cve_id = models.CharField(max_length=32, unique=True, validators=[validate_cve_id_field])
    vendor = models.CharField(max_length=255)
    product = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    short_description = models.TextField()
    date_added = models.DateField()
    due_date = models.DateField()
    ransomware_use = models.BooleanField(default=False)
    cwes = models.TextField(blank=True, default="")
    kev_urls = models.TextField(blank=True, default="")  # newline-joined

    # NVD fields; published/last_modified are kept as NVD's raw strings
    nvd_status = models.CharField(max_length=64, null=True, blank=True)
    nvd_published = models.CharField(max_length=64, null=True, blank=True)
    nvd_last_modified = models.CharField(max_length=64, null=True, blank=True)
    cvss_score = models.FloatField(null=True, blank=True)
    cvss_version = models.CharField(max_length=8, null=True, blank=True)
    cvss_severity = models.CharField(max_length=16, null=True, blank=True)
    cvss_vector = models.CharField(max_length=255, null=True, blank=True)
    cvss_source = models.CharField(max_length=255, null=True, blank=True)
    cvss_type = models.CharField(max_length=32, null=True, blank=True)
    nvd_fetched_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.cve_id

    @property
    def reference_urls(self):
        # Filter again on the way out, in case a bad scheme was planted in the database
        return [url for url in self.kev_urls.split("\n") if url.startswith(("http://", "https://"))]


class Watch(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE)
    note = models.CharField(max_length=500, blank=True, default="")
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "vulnerability"], name="unique_watch_per_user"),
        ]
