"""
API Views for IP Tracking Application
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta

from .models import RequestLog, BlockedIP, SuspiciousIP
from .serializers import (
    RequestLogSerializer,
    BlockedIPSerializer,
    SuspiciousIPSerializer,
    IPStatisticsSerializer
)


class RequestLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing request logs.
    
    List endpoint: GET /api/logs/
    Detail endpoint: GET /api/logs/{id}/
    
    Supports filtering by:
    - ip_address: Filter logs by specific IP
    - country: Filter by country code
    - path: Filter by URL path
    """
    queryset = RequestLog.objects.all()
    serializer_class = RequestLogSerializer
    permission_classes = [AllowAny]
    filterset_fields = ['ip_address', 'country', 'path']
    search_fields = ['ip_address', 'path', 'city']
    ordering_fields = ['timestamp', 'ip_address']
    ordering = ['-timestamp']
    
    @action(detail=False, methods=['get'])
    def by_ip(self, request):
        """
        Get all logs for a specific IP address.
        
        Usage: GET /api/logs/by_ip/?ip=192.168.1.1
        """
        ip_address = request.query_params.get('ip')
        if not ip_address:
            return Response(
                {'error': 'IP address parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        logs = self.queryset.filter(ip_address=ip_address)
        serializer = self.get_serializer(logs, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """
        Get statistics about request logs.
        
        Usage: GET /api/logs/statistics/
        """
        time_filter = request.query_params.get('period', '24h')
        
        # Calculate time range
        if time_filter == '1h':
            time_ago = timezone.now() - timedelta(hours=1)
        elif time_filter == '24h':
            time_ago = timezone.now() - timedelta(hours=24)
        elif time_filter == '7d':
            time_ago = timezone.now() - timedelta(days=7)
        elif time_filter == '30d':
            time_ago = timezone.now() - timedelta(days=30)
        else:
            time_ago = timezone.now() - timedelta(hours=24)
        
        logs = RequestLog.objects.filter(timestamp__gte=time_ago)
        
        # Calculate statistics
        stats = {
            'total_requests': logs.count(),
            'unique_ips': logs.values('ip_address').distinct().count(),
            'blocked_ips': BlockedIP.objects.count(),
            'suspicious_ips': SuspiciousIP.objects.filter(
                flagged_at__gte=time_ago
            ).count(),
            'top_countries': list(
                logs.values('country')
                .annotate(count=Count('id'))
                .order_by('-count')[:10]
            ),
            'top_paths': list(
                logs.values('path')
                .annotate(count=Count('id'))
                .order_by('-count')[:10]
            )
        }
        
        return Response(stats)


class BlockedIPViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing blocked IPs.
    
    List: GET /api/blocked-ips/
    Create: POST /api/blocked-ips/
    Detail: GET /api/blocked-ips/{id}/
    Update: PUT/PATCH /api/blocked-ips/{id}/
    Delete: DELETE /api/blocked-ips/{id}/
    """
    queryset = BlockedIP.objects.all()
    serializer_class = BlockedIPSerializer
    permission_classes = [AllowAny]  # Change to IsAuthenticated in production
    filterset_fields = ['ip_address']
    search_fields = ['ip_address', 'reason']
    ordering_fields = ['blocked_at', 'ip_address']
    ordering = ['-blocked_at']
    
    @action(detail=False, methods=['post'])
    def block_multiple(self, request):
        """
        Block multiple IP addresses at once.
        
        POST /api/blocked-ips/block_multiple/
        Body: {
            "ip_addresses": ["1.2.3.4", "5.6.7.8"],
            "reason": "Spam bots"
        }
        """
        ip_addresses = request.data.get('ip_addresses', [])
        reason = request.data.get('reason', 'Blocked via API')
        
        if not ip_addresses:
            return Response(
                {'error': 'ip_addresses list is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        created = []
        errors = []
        
        for ip in ip_addresses:
            try:
                blocked_ip, was_created = BlockedIP.objects.get_or_create(
                    ip_address=ip,
                    defaults={'reason': reason}
                )
                if was_created:
                    created.append(ip)
                else:
                    errors.append(f'{ip} is already blocked')
            except Exception as e:
                errors.append(f'{ip}: {str(e)}')
        
        return Response({
            'created': created,
            'errors': errors,
            'total_blocked': len(created)
        })
    
    @action(detail=True, methods=['get'])
    def logs(self, request, pk=None):
        """
        Get request logs for this blocked IP.
        
        GET /api/blocked-ips/{id}/logs/
        """
        blocked_ip = self.get_object()
        logs = RequestLog.objects.filter(
            ip_address=blocked_ip.ip_address
        ).order_by('-timestamp')[:100]
        
        serializer = RequestLogSerializer(logs, many=True)
        return Response(serializer.data)


class SuspiciousIPViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing suspicious IPs.
    
    List: GET /api/suspicious-ips/
    Detail: GET /api/suspicious-ips/{id}/
    Update: PUT/PATCH /api/suspicious-ips/{id}/
    Delete: DELETE /api/suspicious-ips/{id}/ (dismiss flag)
    """
    queryset = SuspiciousIP.objects.all()
    serializer_class = SuspiciousIPSerializer
    permission_classes = [AllowAny]  # Change to IsAuthenticated in production
    filterset_fields = ['ip_address']
    search_fields = ['ip_address', 'reason']
    ordering_fields = ['flagged_at', 'request_count']
    ordering = ['-flagged_at']
    
    @action(detail=True, methods=['post'])
    def block(self, request, pk=None):
        """
        Block this suspicious IP address.
        
        POST /api/suspicious-ips/{id}/block/
        Body: {
            "reason": "Optional custom reason"
        }
        """
        suspicious_ip = self.get_object()
        custom_reason = request.data.get('reason')
        
        reason = custom_reason or f'Blocked from suspicious activity: {suspicious_ip.reason}'
        
        blocked_ip, created = BlockedIP.objects.get_or_create(
            ip_address=suspicious_ip.ip_address,
            defaults={'reason': reason}
        )
        
        if created:
            return Response({
                'status': 'success',
                'message': f'IP {suspicious_ip.ip_address} has been blocked',
                'blocked_ip': BlockedIPSerializer(blocked_ip).data
            })
        else:
            return Response({
                'status': 'already_blocked',
                'message': f'IP {suspicious_ip.ip_address} is already blocked',
                'blocked_ip': BlockedIPSerializer(blocked_ip).data
            })
    
    @action(detail=True, methods=['post'])
    def dismiss(self, request, pk=None):
        """
        Dismiss this suspicious IP flag (false positive).
        
        POST /api/suspicious-ips/{id}/dismiss/
        """
        suspicious_ip = self.get_object()
        ip_address = suspicious_ip.ip_address
        suspicious_ip.delete()
        
        return Response({
            'status': 'success',
            'message': f'Flag for IP {ip_address} has been dismissed'
        })
    
    @action(detail=False, methods=['post'])
    def block_all(self, request):
        """
        Block all currently flagged suspicious IPs.
        
        POST /api/suspicious-ips/block_all/
        """
        suspicious_ips = self.queryset.all()
        blocked_count = 0
        
        for suspicious_ip in suspicious_ips:
            _, created = BlockedIP.objects.get_or_create(
                ip_address=suspicious_ip.ip_address,
                defaults={
                    'reason': f'Auto-blocked: {suspicious_ip.reason}'
                }
            )
            if created:
                blocked_count += 1
        
        return Response({
            'status': 'success',
            'blocked_count': blocked_count,
            'message': f'Blocked {blocked_count} suspicious IPs'
        })
    
    @action(detail=False, methods=['get'])
    def recent(self, request):
        """
        Get suspicious IPs flagged in the last 24 hours.
        
        GET /api/suspicious-ips/recent/
        """
        yesterday = timezone.now() - timedelta(hours=24)
        recent_suspicious = self.queryset.filter(flagged_at__gte=yesterday)
        
        serializer = self.get_serializer(recent_suspicious, many=True)
        return Response(serializer.data)


@api_view(['GET'])
def health_check(request):
    """
    Simple health check endpoint.
    
    GET /api/health/
    """
    from django.db import connection
    
    try:
        # Check database connection
        connection.ensure_connection()
        db_status = 'healthy'
    except Exception:
        db_status = 'unhealthy'
    
    try:
        # Check cache connection
        from django.core.cache import cache
        cache.set('health_check', 'ok', 10)
        cache_status = 'healthy'
    except Exception:
        cache_status = 'unhealthy'
    
    return Response({
        'status': 'ok',
        'database': db_status,
        'cache': cache_status,
        'timestamp': timezone.now().isoformat()
    })


@api_view(['GET'])
def dashboard_stats(request):
    """
    Get dashboard statistics for frontend.
    
    GET /api/dashboard/
    """
    # Last 24 hours
    yesterday = timezone.now() - timedelta(hours=24)
    
    stats = {
        'requests_24h': RequestLog.objects.filter(timestamp__gte=yesterday).count(),
        'unique_ips_24h': RequestLog.objects.filter(
            timestamp__gte=yesterday
        ).values('ip_address').distinct().count(),
        'blocked_ips_total': BlockedIP.objects.count(),
        'suspicious_ips_24h': SuspiciousIP.objects.filter(
            flagged_at__gte=yesterday
        ).count(),
        'top_countries': list(
            RequestLog.objects.filter(timestamp__gte=yesterday, country__isnull=False)
            .values('country')
            .annotate(count=Count('id'))
            .order_by('-count')[:5]
        ),
        'recent_blocked': BlockedIPSerializer(
            BlockedIP.objects.all().order_by('-blocked_at')[:5],
            many=True
        ).data,
        'recent_suspicious': SuspiciousIPSerializer(
            SuspiciousIP.objects.all().order_by('-flagged_at')[:5],
            many=True
        ).data
    }
    
    return Response(stats)