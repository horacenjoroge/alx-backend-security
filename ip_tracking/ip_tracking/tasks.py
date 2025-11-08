from celery import shared_task
from django.utils import timezone
from django.db.models import Count
from django.conf import settings
from datetime import timedelta
import logging

from .models import RequestLog, SuspiciousIP, BlockedIP

logger = logging.getLogger(__name__)


@shared_task(name='ip_tracking.tasks.detect_anomalies')
def detect_anomalies():
    """
    Detect and flag suspicious IP addresses based on behavior patterns.
    
    This task runs hourly and checks for:
    1. IPs making too many requests (> 100/hour by default)
    2. IPs accessing sensitive paths repeatedly
    
    Flagged IPs are added to the SuspiciousIP model for review.
    Administrators can then decide whether to block them.
    """
    logger.info("Starting anomaly detection task")
    
    # Get the threshold from settings or use default
    threshold = getattr(settings, 'IP_TRACKING_ANOMALY_THRESHOLD', 100)
    sensitive_paths = getattr(settings, 'IP_TRACKING_SENSITIVE_PATHS', [
        '/admin/', '/login/', '/api/auth/', '/api/payment/'
    ])
    
    # Look at requests from the last hour
    one_hour_ago = timezone.now() - timedelta(hours=1)
    
    # Find IPs with excessive request counts
    high_traffic_ips = (
        RequestLog.objects
        .filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(request_count=Count('id'))
        .filter(request_count__gt=threshold)
    )
    
    flagged_count = 0
    
    for ip_data in high_traffic_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        
        # Skip if already blocked
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            continue
        
        # Check if we've already flagged this IP recently (last 24 hours)
        recent_flag = SuspiciousIP.objects.filter(
            ip_address=ip_address,
            flagged_at__gte=timezone.now() - timedelta(hours=24)
        ).exists()
        
        if not recent_flag:
            SuspiciousIP.objects.create(
                ip_address=ip_address,
                reason=f'Excessive requests: {request_count} requests in the last hour',
                request_count=request_count
            )
            flagged_count += 1
            logger.warning(
                f"Flagged IP {ip_address} for excessive requests: {request_count}/hour"
            )
    
    # Find IPs accessing sensitive paths repeatedly
    for sensitive_path in sensitive_paths:
        sensitive_access_ips = (
            RequestLog.objects
            .filter(
                timestamp__gte=one_hour_ago,
                path__startswith=sensitive_path
            )
            .values('ip_address')
            .annotate(access_count=Count('id'))
            .filter(access_count__gt=10)  # More than 10 accesses to sensitive path
        )
        
        for ip_data in sensitive_access_ips:
            ip_address = ip_data['ip_address']
            access_count = ip_data['access_count']
            
            # Skip if already blocked or flagged
            if BlockedIP.objects.filter(ip_address=ip_address).exists():
                continue
            
            recent_flag = SuspiciousIP.objects.filter(
                ip_address=ip_address,
                flagged_at__gte=timezone.now() - timedelta(hours=24)
            ).exists()
            
            if not recent_flag:
                SuspiciousIP.objects.create(
                    ip_address=ip_address,
                    reason=f'Repeated access to sensitive path {sensitive_path}: {access_count} times in last hour',
                    request_count=access_count
                )
                flagged_count += 1
                logger.warning(
                    f"Flagged IP {ip_address} for accessing {sensitive_path} {access_count} times"
                )
    
    logger.info(f"Anomaly detection complete. Flagged {flagged_count} new suspicious IPs")
    return {
        'flagged_count': flagged_count,
        'checked_at': timezone.now().isoformat()
    }


@shared_task(name='ip_tracking.tasks.cleanup_old_logs')
def cleanup_old_logs():
    """
    Delete old request logs to prevent database bloat.
    
    This task runs daily and removes logs older than the configured
    retention period (default: 90 days).
    
    Privacy benefit: Helps with GDPR/CCPA compliance by not keeping
    data longer than necessary.
    """
    logger.info("Starting log cleanup task")
    
    # Get retention period from settings
    retention_days = getattr(settings, 'IP_TRACKING_LOG_RETENTION_DAYS', 90)
    cutoff_date = timezone.now() - timedelta(days=retention_days)
    
    # Delete old logs
    deleted_count, _ = RequestLog.objects.filter(
        timestamp__lt=cutoff_date
    ).delete()
    
    logger.info(f"Deleted {deleted_count} logs older than {retention_days} days")
    return {
        'deleted_count': deleted_count,
        'cutoff_date': cutoff_date.isoformat()
    }


@shared_task(name='ip_tracking.tasks.analyze_suspicious_ips')
def analyze_suspicious_ips():
    """
    Advanced analysis of suspicious IPs.
    
    This optional task can be extended to:
    - Check IPs against threat intelligence databases
    - Perform more sophisticated pattern analysis
    - Send alerts to administrators
    - Auto-block IPs that meet certain criteria
    """
    logger.info("Starting suspicious IP analysis")
    
    # Get recently flagged IPs (last 7 days)
    recent_suspicious = SuspiciousIP.objects.filter(
        flagged_at__gte=timezone.now() - timedelta(days=7)
    )
    
    auto_blocked = 0
    
    for suspicious_ip in recent_suspicious:
        # Check if this IP has been flagged multiple times
        flag_count = SuspiciousIP.objects.filter(
            ip_address=suspicious_ip.ip_address
        ).count()
        
        # Auto-block if flagged 3+ times and not already blocked
        if flag_count >= 3:
            if not BlockedIP.objects.filter(ip_address=suspicious_ip.ip_address).exists():
                BlockedIP.objects.create(
                    ip_address=suspicious_ip.ip_address,
                    reason=f'Automatically blocked: Flagged {flag_count} times for suspicious activity'
                )
                auto_blocked += 1
                logger.warning(f"Auto-blocked IP {suspicious_ip.ip_address} after {flag_count} flags")
    
    logger.info(f"Suspicious IP analysis complete. Auto-blocked {auto_blocked} IPs")
    return {
        'auto_blocked': auto_blocked,
        'analyzed_at': timezone.now().isoformat()
    }


@shared_task(name='ip_tracking.tasks.generate_security_report')
def generate_security_report():
    """
    Generate a daily security report.
    
    This task creates a summary of:
    - Total requests in the last 24 hours
    - Top IP addresses by request count
    - Blocked and suspicious IP counts
    - Geographic distribution of requests
    
    In production, this could send an email or store the report.
    """
    logger.info("Generating security report")
    
    yesterday = timezone.now() - timedelta(days=1)
    
    # Total requests
    total_requests = RequestLog.objects.filter(timestamp__gte=yesterday).count()
    
    # Top IPs
    top_ips = (
        RequestLog.objects
        .filter(timestamp__gte=yesterday)
        .values('ip_address')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )
    
    # Security metrics
    blocked_count = BlockedIP.objects.count()
    suspicious_count = SuspiciousIP.objects.filter(flagged_at__gte=yesterday).count()
    
    # Geographic distribution
    countries = (
        RequestLog.objects
        .filter(timestamp__gte=yesterday, country__isnull=False)
        .values('country')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )
    
    report = {
        'date': timezone.now().isoformat(),
        'total_requests': total_requests,
        'top_ips': list(top_ips),
        'blocked_ips': blocked_count,
        'new_suspicious_ips': suspicious_count,
        'top_countries': list(countries)
    }
    
    logger.info(f"Security report generated: {total_requests} requests, {suspicious_count} new suspicious IPs")
    
    # In production, you might:
    # - Send this via email
    # - Store in a Report model
    # - Push to a monitoring dashboard
    
    return report