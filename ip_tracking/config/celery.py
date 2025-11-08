"""
Celery configuration for IP tracking.

This file tells Celery:
- Where to find Django settings
- How to connect to Redis (message broker)
- Where to discover tasks
"""

import os
from celery import Celery

# Set the default Django settings module for the 'celery' program.
# This MUST match your Django project name (config in your case)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

# Create the Celery application
# The name 'config' should match your Django project name
app = Celery('config')

# Load configuration from Django settings
# namespace='CELERY' means all celery-related settings start with 'CELERY_'
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks in all installed Django apps
# This looks for tasks.py in each app (like ip_tracking/tasks.py)
app.autodiscover_tasks()


@app.task(bind=True, ignore_result=True)
def debug_task(self):
    """
    A debug task to test if Celery is working.
    Run with: celery -A config call config.celery.debug_task
    """
    print(f'Request: {self.request!r}')