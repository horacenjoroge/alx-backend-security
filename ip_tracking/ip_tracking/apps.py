from django.apps import AppConfig


class IpTrackingConfig(AppConfig):
    """
    Configuration for the IP Tracking application.
    
    This app provides:
    - Request logging with geolocation
    - IP blacklisting
    - Rate limiting
    - Anomaly detection
    """
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ip_tracking'
    verbose_name = 'IP Tracking & Security'
    
    def ready(self):
        """
        Code to run when Django starts.
        
        This is a good place to:
        - Register signals
        - Import Celery tasks
        - Initialize components
        """
        # Import tasks to ensure Celery discovers them
        try:
            from . import tasks  # noqa
        except ImportError:
            pass