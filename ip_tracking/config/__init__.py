"""
This makes sure Celery app is imported when Django starts.

This is important because it:
1. Loads the Celery configuration
2. Registers all @shared_task decorators
3. Connects to Redis
"""

# Import the Celery app
from .celery import app as celery_app

# This tells Python what to export from this module
__all__ = ('celery_app',)