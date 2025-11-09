"""
URL configuration for IP Tracking project with Swagger documentation.

This file configures:
- Admin interface
- REST API endpoints
- Swagger/OpenAPI documentation
- ReDoc documentation
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers, permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

# Import API views
from ip_tracking import api_views

# Configure REST API Router
router = routers.DefaultRouter()
router.register(r'logs', api_views.RequestLogViewSet, basename='requestlog')
router.register(r'blocked-ips', api_views.BlockedIPViewSet, basename='blockedip')
router.register(r'suspicious-ips', api_views.SuspiciousIPViewSet, basename='suspiciousip')

# Configure Swagger/OpenAPI Schema
schema_view = get_schema_view(
    openapi.Info(
        title="IP Tracking & Security API",
        default_version='v1',
        description="""
# IP Tracking & Security Management API

This API provides endpoints for:

## Features
- **Request Logging**: Track all incoming requests with geolocation data
- **IP Blacklisting**: Manage blocked IP addresses
- **Anomaly Detection**: Monitor and flag suspicious IP behavior
- **Statistics**: Get insights on traffic patterns and security metrics

## Authentication
Currently, all endpoints are publicly accessible. In production, you should:
1. Enable authentication (Token/JWT/OAuth)
2. Set appropriate permissions
3. Rate limit API requests

## Rate Limiting
API endpoints are rate-limited to prevent abuse:
- Anonymous users: 100 requests/hour
- Authenticated users: 1000 requests/hour

## Endpoints Overview
- `/api/logs/` - View request logs
- `/api/blocked-ips/` - Manage blocked IPs
- `/api/suspicious-ips/` - Review flagged IPs
- `/api/health/` - Health check endpoint
- `/api/dashboard/` - Dashboard statistics

## Support
For issues or questions, contact your system administrator.
        """,
        terms_of_service="https://www.yourapp.com/terms/",
        contact=openapi.Contact(email="admin@yourapp.com"),
        license=openapi.License(name="MIT License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
    patterns=[
        path('api/', include(router.urls)),
    ],
)

urlpatterns = [
    # Admin Interface
    path('admin/', admin.site.urls),
    
    # API Endpoints
    path('api/', include(router.urls)),
    path('api/health/', api_views.health_check, name='health-check'),
    path('api/dashboard/', api_views.dashboard_stats, name='dashboard-stats'),
    
    # Swagger Documentation Endpoints
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('swagger.json', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger.yaml', schema_view.without_ui(cache_timeout=0), name='schema-yaml'),
    
    # ReDoc Documentation (Alternative to Swagger UI)
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    
    # API Authentication (if using DRF's built-in auth)
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
]

# Optional: Custom error handlers
# handler404 = 'ip_tracking.views.custom_404'
# handler500 = 'ip_tracking.views.custom_500'