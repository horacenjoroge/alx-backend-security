from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit
from django.shortcuts import render


def get_rate_limit_key(group, request):
    """
    Custom function to determine rate limit key.
    
    This allows us to apply different limits for authenticated vs anonymous users.
    Authenticated users get their user ID as the key, anonymous get their IP.
    """
    if request.user.is_authenticated:
        return f'user_{request.user.id}'
    return request.META.get('REMOTE_ADDR', 'unknown')


@ratelimit(
    key='ip',  # Rate limit by IP address
    rate='5/m',  # 5 requests per minute for anonymous users
    method='POST'
)
@ratelimit(
    key='user',  # Rate limit by user for authenticated users
    rate='10/m',  # 10 requests per minute for authenticated users
    method='POST'
)
@require_http_methods(["GET", "POST"])
def login_view(request):
    """
    Login view with rate limiting.
    
    Rate limits:
    - Anonymous users: 5 attempts per minute (by IP)
    - Authenticated users: 10 attempts per minute (by user ID)
    
    This prevents brute force attacks while allowing legitimate users
    to retry failed login attempts.
    """
    # Check if the request was rate limited
    # The @ratelimit decorator adds a 'limited' attribute
    if getattr(request, 'limited', False):
        return JsonResponse({
            'error': 'Too many login attempts. Please try again later.',
            'retry_after': '60 seconds'
        }, status=429)  # 429 Too Many Requests
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if not username or not password:
            return JsonResponse({
                'error': 'Username and password are required'
            }, status=400)
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return JsonResponse({
                'success': True,
                'message': 'Login successful',
                'user': username
            })
        else:
            return JsonResponse({
                'error': 'Invalid credentials'
            }, status=401)
    
    # GET request - show login form
    return render(request, 'login.html')


@ratelimit(
    key='ip',
    rate='5/m',
    method='POST'
)
@ratelimit(
    key='user',
    rate='10/m',
    method='POST'
)
@require_http_methods(["POST"])
def api_endpoint(request):
    """
    Example API endpoint with rate limiting.
    
    This demonstrates how to protect any sensitive endpoint.
    The pattern is the same as login_view.
    """
    if getattr(request, 'limited', False):
        return JsonResponse({
            'error': 'Rate limit exceeded',
            'message': 'You have made too many requests. Please slow down.'
        }, status=429)
    
    # Your API logic here
    return JsonResponse({
        'success': True,
        'data': 'Your API response'
    })


@login_required
@ratelimit(key='user', rate='20/m', method=['GET', 'POST'])
def dashboard_view(request):
    """
    Protected dashboard with higher rate limit for authenticated users.
    
    Since users must be logged in, we only rate limit by user ID.
    The higher limit (20/min) is appropriate for interactive pages.
    """
    if getattr(request, 'limited', False):
        return JsonResponse({
            'error': 'Rate limit exceeded'
        }, status=429)
    
    return render(request, 'dashboard.html', {
        'user': request.user
    })


# Example: Rate limiting for different user tiers
@ratelimit(
    key='user_or_ip',
    rate='100/h',  # Free tier: 100 requests/hour
    method='ALL'
)
def free_api_endpoint(request):
    """
    API endpoint for free tier users.
    
    In a real application, you'd check the user's subscription level
    and apply different rate limits accordingly.
    """
    if getattr(request, 'limited', False):
        return JsonResponse({
            'error': 'Free tier rate limit exceeded',
            'message': 'Upgrade to premium for higher limits',
            'limit': '100 requests per hour'
        }, status=429)
    
    return JsonResponse({'data': 'Free tier response'})