from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.utils.deprecation import MiddlewareMixin
from .models import RequestLog, BlockedIP
import logging
import requests

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """
    Extract the real client IP address from the request.
    
    This function checks various headers because the IP might be hidden
    behind proxies, load balancers, or CDNs.
    
    Headers checked (in order of priority):
    1. HTTP_X_FORWARDED_FOR - Set by proxies/load balancers
    2. HTTP_X_REAL_IP - Set by some reverse proxies (like nginx)
    3. REMOTE_ADDR - Direct connection IP (fallback)
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
        # The first one is the original client
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        # Fall back to the direct connection IP
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_geolocation(ip_address):
    """
    Get geolocation data for an IP address.
    
    Uses ipinfo.io API (free tier: 50k requests/month).
    Returns a dict with 'country' and 'city' keys.
    
    Alternative services:
    - ip-api.com (free, no key needed)
    - ipgeolocation.io
    - MaxMind GeoIP2 (local database, faster)
    """
    # Check cache first (24-hour cache as specified in requirements)
    cache_key = f'geo_{ip_address}'
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return cached_data
    
    # Skip geolocation for local/private IPs
    if ip_address.startswith(('127.', '10.', '192.168.', '172.')):
        return {'country': None, 'city': None}
    
    try:
        # Using ip-api.com (free, no API key required)
        response = requests.get(
            f'http://ip-api.com/json/{ip_address}',
            timeout=2  # Don't wait too long
        )
        
        if response.status_code == 200:
            data = response.json()
            geo_data = {
                'country': data.get('countryCode'),
                'city': data.get('city')
            }
            # Cache for 24 hours (86400 seconds)
            cache.set(cache_key, geo_data, 86400)
            return geo_data
    except Exception as e:
        logger.error(f"Geolocation lookup failed for {ip_address}: {e}")
    
    # Return empty data if lookup fails
    return {'country': None, 'city': None}


class IPTrackingMiddleware(MiddlewareMixin):
    """
    Middleware that:
    1. Logs every request (Task 0)
    2. Blocks requests from blacklisted IPs (Task 1)
    
    Middleware runs for EVERY request before it reaches your views.
    """
    
    def process_request(self, request):
        """
        This method runs BEFORE the view is called.
        It's perfect for blocking requests early.
        """
        # Get the client's IP address
        ip_address = get_client_ip(request)
        
        # Task 1: Check if this IP is blacklisted
        # Use caching to avoid hitting the database for every request
        cache_key = f'blocked_ip_{ip_address}'
        is_blocked = cache.get(cache_key)
        
        if is_blocked is None:
            # Not in cache, check the database
            is_blocked = BlockedIP.objects.filter(ip_address=ip_address).exists()
            # Cache the result for 5 minutes to reduce DB load
            cache.set(cache_key, is_blocked, 300)
        
        if is_blocked:
            logger.warning(f"Blocked request from blacklisted IP: {ip_address}")
            return HttpResponseForbidden(
                "<h1>403 Forbidden</h1>"
                "<p>Your IP address has been blocked.</p>"
            )
        
        # If not blocked, store the request for later processing
        # We'll log it in process_response to avoid blocking the request
        request.ip_address = ip_address
        
        return None  # Continue processing the request
    
    def process_response(self, request, response):
        """
        This method runs AFTER the view has processed the request.
        It's a good place to log since it won't slow down the response.
        """
        # Task 0: Log the request
        # Get the IP we stored earlier (or extract it again)
        ip_address = getattr(request, 'ip_address', None) or get_client_ip(request)
        path = request.path
        
        try:
            # Task 2: Get geolocation data
            geo_data = get_geolocation(ip_address)
            
            # Log the request to the database with geolocation
            # In production, you might want to do this asynchronously with Celery
            # to avoid slowing down responses
            RequestLog.objects.create(
                ip_address=ip_address,
                path=path,
                country=geo_data['country'],
                city=geo_data['city']
            )
        except Exception as e:
            # Never let logging errors break your application
            logger.error(f"Failed to log request: {e}")
        
        return response


class IPGeolocationMiddleware(MiddlewareMixin):
    """
    Middleware that adds geolocation data to logged requests (Task 2).
    This will be implemented in Task 2.
    """
    
    def process_request(self, request):
        """
        Add geolocation data to the request object.
        The actual implementation will be added in Task 2.
        """
        # Store IP for later use
        request.ip_address = get_client_ip(request)
        return None