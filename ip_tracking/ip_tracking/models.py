from django.db import models
from django.utils import timezone


class RequestLog(models.Model):
    """
    Stores information about each request to track visitor activity.
    
    Fields:
    - ip_address: The visitor's IP address
    - timestamp: When the request was made
    - path: Which URL was accessed
    - country: Country code from geolocation (Task 2)
    - city: City name from geolocation (Task 2)
    """
    ip_address = models.GenericIPAddressField(
        help_text="IP address of the client making the request"
    )
    timestamp = models.DateTimeField(
        default=timezone.now,
        db_index=True,  # Index for faster queries by time
        help_text="When the request was made"
    )
    path = models.CharField(
        max_length=500,
        help_text="The URL path that was requested"
    )
    # Task 2: Geolocation fields
    country = models.CharField(
        max_length=2,
        blank=True,
        null=True,
        help_text="Two-letter country code (e.g., US, GB, FR)"
    )
    city = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="City name from geolocation"
    )
    
    class Meta:
        ordering = ['-timestamp']  # Show newest requests first
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),  # For IP-based queries
        ]
    
    def __str__(self):
        return f"{self.ip_address} - {self.path} at {self.timestamp}"


class BlockedIP(models.Model):
    """
    List of IP addresses that should be blocked from accessing the site.
    Used in Task 1 for IP blacklisting.
    """
    ip_address = models.GenericIPAddressField(
        unique=True,
        help_text="IP address to block"
    )
    reason = models.TextField(
        blank=True,
        help_text="Why this IP was blocked"
    )
    blocked_at = models.DateTimeField(
        default=timezone.now,
        help_text="When this IP was blocked"
    )
    
    class Meta:
        ordering = ['-blocked_at']
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
    
    def __str__(self):
        return f"Blocked: {self.ip_address}"


class SuspiciousIP(models.Model):
    """
    Tracks IPs that show suspicious behavior patterns.
    Used in Task 4 for anomaly detection.
    """
    ip_address = models.GenericIPAddressField(
        help_text="IP address flagged as suspicious"
    )
    reason = models.TextField(
        help_text="Why this IP was flagged (e.g., too many requests, accessing sensitive paths)"
    )
    flagged_at = models.DateTimeField(
        default=timezone.now,
        db_index=True,
        help_text="When this IP was flagged"
    )
    request_count = models.IntegerField(
        default=0,
        help_text="Number of requests made in the detection window"
    )
    
    class Meta:
        ordering = ['-flagged_at']
        indexes = [
            models.Index(fields=['ip_address', 'flagged_at']),
        ]
    
    def __str__(self):
        return f"Suspicious: {self.ip_address} - {self.reason}"