"""
Serializers for IP Tracking API
"""
from rest_framework import serializers
from .models import RequestLog, BlockedIP, SuspiciousIP


class RequestLogSerializer(serializers.ModelSerializer):
    """
    Serializer for RequestLog model.
    Converts model instances to JSON for API responses.
    """
    class Meta:
        model = RequestLog
        fields = [
            'id',
            'ip_address',
            'timestamp',
            'path',
            'country',
            'city'
        ]
        read_only_fields = ['id', 'timestamp']


class BlockedIPSerializer(serializers.ModelSerializer):
    """
    Serializer for BlockedIP model.
    """
    class Meta:
        model = BlockedIP
        fields = [
            'id',
            'ip_address',
            'reason',
            'blocked_at'
        ]
        read_only_fields = ['id', 'blocked_at']
    
    def validate_ip_address(self, value):
        """
        Validate IP address format.
        """
        import ipaddress
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise serializers.ValidationError("Invalid IP address format")
        return value


class SuspiciousIPSerializer(serializers.ModelSerializer):
    """
    Serializer for SuspiciousIP model.
    """
    is_blocked = serializers.SerializerMethodField()
    
    class Meta:
        model = SuspiciousIP
        fields = [
            'id',
            'ip_address',
            'reason',
            'flagged_at',
            'request_count',
            'is_blocked'
        ]
        read_only_fields = ['id', 'flagged_at']
    
    def get_is_blocked(self, obj):
        """
        Check if this IP is currently blocked.
        """
        return BlockedIP.objects.filter(ip_address=obj.ip_address).exists()


class IPStatisticsSerializer(serializers.Serializer):
    """
    Serializer for IP statistics summary.
    """
    total_requests = serializers.IntegerField()
    unique_ips = serializers.IntegerField()
    blocked_ips = serializers.IntegerField()
    suspicious_ips = serializers.IntegerField()
    top_countries = serializers.ListField()
    top_paths = serializers.ListField()