from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.db.models import Count
from .models import RequestLog, BlockedIP, SuspiciousIP


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    """
    Admin interface for viewing request logs.
    
    Features:
    - Search by IP or path
    - Filter by country, city, date
    - Display geolocation data
    - Click IP to see all requests from that IP
    """
    list_display = [
        'ip_address_link',
        'path',
        'country_flag',
        'city',
        'timestamp'
    ]
    list_filter = [
        'country',
        'timestamp',
        ('city', admin.EmptyFieldListFilter),
    ]
    search_fields = ['ip_address', 'path']
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']
    
    # Read-only fields (logs shouldn't be edited)
    readonly_fields = ['ip_address', 'path', 'country', 'city', 'timestamp']
    
    # Show 50 items per page
    list_per_page = 50
    
    def ip_address_link(self, obj):
        """
        Make IP address clickable to filter by that IP
        """
        url = reverse('admin:ip_tracking_requestlog_changelist')
        return format_html(
            '<a href="{}?ip_address={}">{}</a>',
            url,
            obj.ip_address,
            obj.ip_address
        )
    ip_address_link.short_description = 'IP Address'
    
    def country_flag(self, obj):
        """
        Display country with emoji flag (if available)
        """
        if obj.country:
            # Convert country code to flag emoji
            # This works because flag emojis are regional indicators
            flag = ''.join(chr(127397 + ord(c)) for c in obj.country.upper())
            return format_html('{} {}', flag, obj.country)
        return '—'
    country_flag.short_description = 'Country'
    
    def has_add_permission(self, request):
        """
        Disable manual addition of logs (they're created automatically)
        """
        return False
    
    def has_change_permission(self, request, obj=None):
        """
        Make logs read-only
        """
        return False


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    """
    Admin interface for managing blocked IPs.
    
    Features:
    - Add/remove IPs from blacklist
    - View block reason and date
    - Search and filter
    - Bulk actions
    """
    list_display = [
        'ip_address',
        'reason_preview',
        'blocked_at',
        'view_logs_link'
    ]
    list_filter = ['blocked_at']
    search_fields = ['ip_address', 'reason']
    date_hierarchy = 'blocked_at'
    ordering = ['-blocked_at']
    
    # Fields to show when adding/editing
    fields = ['ip_address', 'reason', 'blocked_at']
    readonly_fields = ['blocked_at']
    
    def reason_preview(self, obj):
        """
        Show first 50 characters of reason
        """
        if len(obj.reason) > 50:
            return obj.reason[:50] + '...'
        return obj.reason
    reason_preview.short_description = 'Reason'
    
    def view_logs_link(self, obj):
        """
        Link to view all logs from this IP
        """
        url = reverse('admin:ip_tracking_requestlog_changelist')
        count = RequestLog.objects.filter(ip_address=obj.ip_address).count()
        return format_html(
            '<a href="{}?ip_address={}">View {} logs</a>',
            url,
            obj.ip_address,
            count
        )
    view_logs_link.short_description = 'Logs'
    
    actions = ['bulk_unblock']
    
    def bulk_unblock(self, request, queryset):
        """
        Bulk action to unblock selected IPs
        """
        count = queryset.count()
        queryset.delete()
        self.message_user(
            request,
            f'Successfully unblocked {count} IP(s).'
        )
    bulk_unblock.short_description = 'Unblock selected IPs'


@admin.register(SuspiciousIP)
class SuspiciousIPAdmin(admin.ModelAdmin):
    """
    Admin interface for reviewing flagged IPs.
    
    Features:
    - Review suspicious activity
    - See reason and request count
    - Block suspicious IPs directly
    - View related logs
    """
    list_display = [
        'ip_address',
        'reason_preview',
        'request_count',
        'flagged_at',
        'is_blocked',
        'view_logs_link'
    ]
    list_filter = ['flagged_at']
    search_fields = ['ip_address', 'reason']
    date_hierarchy = 'flagged_at'
    ordering = ['-flagged_at']
    
    # Read-only (these are auto-generated)
    readonly_fields = ['ip_address', 'reason', 'request_count', 'flagged_at']
    
    def reason_preview(self, obj):
        """
        Show truncated reason
        """
        if len(obj.reason) > 60:
            return obj.reason[:60] + '...'
        return obj.reason
    reason_preview.short_description = 'Reason'
    
    def is_blocked(self, obj):
        """
        Show if this IP is currently blocked
        """
        blocked = BlockedIP.objects.filter(ip_address=obj.ip_address).exists()
        if blocked:
            return format_html(
                '<span style="color: red; font-weight: bold;">✓ BLOCKED</span>'
            )
        return '—'
    is_blocked.short_description = 'Status'
    
    def view_logs_link(self, obj):
        """
        Link to view logs from this IP
        """
        url = reverse('admin:ip_tracking_requestlog_changelist')
        return format_html(
            '<a href="{}?ip_address={}">View logs</a>',
            url,
            obj.ip_address
        )
    view_logs_link.short_description = 'Logs'
    
    actions = ['block_ips', 'dismiss_flags']
    
    def block_ips(self, request, queryset):
        """
        Bulk action to block flagged IPs
        """
        blocked_count = 0
        for suspicious_ip in queryset:
            BlockedIP.objects.get_or_create(
                ip_address=suspicious_ip.ip_address,
                defaults={
                    'reason': f'Auto-blocked: {suspicious_ip.reason}'
                }
            )
            blocked_count += 1
        
        self.message_user(
            request,
            f'Successfully blocked {blocked_count} IP(s).'
        )
    block_ips.short_description = 'Block selected IPs'
    
    def dismiss_flags(self, request, queryset):
        """
        Bulk action to dismiss false positives
        """
        count = queryset.count()
        queryset.delete()
        self.message_user(
            request,
            f'Dismissed {count} flag(s).'
        )
    dismiss_flags.short_description = 'Dismiss selected flags'
    
    def has_add_permission(self, request):
        """
        Disable manual addition (flags are auto-generated)
        """
        return False


# Customize the admin site header
admin.site.site_header = 'IP Tracking Administration'
admin.site.site_title = 'IP Tracking Admin'
admin.site.index_title = 'IP Tracking & Security Management'