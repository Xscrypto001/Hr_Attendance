# views.py
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views.generic import View
from django.db import transaction
from django.contrib.auth.hashers import make_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
import json
from .models import User, LoginActivity, UserProfile
from .forms import UserRegistrationForm, UserLoginForm

def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

class AuthView(View):
    """Main authentication view"""
    
    def get(self, request):
        """Display login/signup page"""
        if request.user.is_authenticated:
            return redirect('dashboard')
        
        context = {
            'roles': User.ROLE_CHOICES,
        }
        return render(request, 'auth/login_signup.html', context)

class LoginView(View):
    """Handle user login"""
    
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    
    def post(self, request):
        """Process login request"""
        try:
            # Handle both JSON and form data
            if request.content_type == 'application/json':
                data = json.loads(request.body)
            else:
                data = request.POST
            
            email = data.get('email', '').strip().lower()
            password = data.get('password', '')
            role = data.get('role', '')
            
            # Validate input
            if not email or not password or not role:
                return JsonResponse({
                    'success': False,
                    'message': 'All fields are required'
                }, status=400)
            
            # Validate email format
            try:
                validate_email(email)
            except ValidationError:
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid email format'
                }, status=400)
            
            # Check if user exists with this email and role
            try:
                user = User.objects.get(email=email, role=role)
            except User.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid credentials or role'
                }, status=401)
            
            # Authenticate user
            user = authenticate(request, username=email, password=password)
            
            if user and user.is_active:
                # Check if the role matches
                if user.role != role:
                    return JsonResponse({
                        'success': False,
                        'message': 'Invalid role for this account'
                    }, status=401)
                
                login(request, user)
                
                # Log login activity
                LoginActivity.objects.create(
                    user=user,
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    role_used=role
                )
                
                # Return success response
                return JsonResponse({
                    'success': True,
                    'message': 'Login successful',
                    'redirect_url': self.get_redirect_url(user.role),
                    'user': {
                        'id': user.id,
                        'name': user.full_name,
                        'email': user.email,
                        'role': user.role,
                        'role_display': user.get_role_display_icon()
                    }
                })
            
            else:
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid credentials'
                }, status=401)
        
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': 'An error occurred during login'
            }, status=500)
    
    def get_redirect_url(self, role):
        """Get redirect URL based on user role"""
        role_redirects = {
            'admin': '/admin-dashboard/',
            'hr_manager': '/hr-dashboard/',
            'hr_assistant': '/hr-assistant-dashboard/',
            'employee': '/employee-dashboard/',
            'manager': '/manager-dashboard/',
        }
        return role_redirects.get(role, '/dashboard/')

class SignupView(View):
    """Handle user registration"""
    
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    
    def post(self, request):
        """Process signup request"""
        try:
            # Handle both JSON and form data
            if request.content_type == 'application/json':
                data = json.loads(request.body)
            else:
                data = request.POST
            
            name = data.get('name', '').strip()
            email = data.get('email', '').strip().lower()
            password = data.get('password', '')
            confirm_password = data.get('confirm_password', '')
            role = data.get('role', '')
            
            # Validate input
            if not all([name, email, password, confirm_password, role]):
                return JsonResponse({
                    'success': False,
                    'message': 'All fields are required'
                }, status=400)
            
            # Validate email format
            try:
                validate_email(email)
            except ValidationError:
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid email format'
                }, status=400)
            
            # Check password match
            if password != confirm_password:
                return JsonResponse({
                    'success': False,
                    'message': 'Passwords do not match'
                }, status=400)
            
            # Check password strength
            if len(password) < 8:
                return JsonResponse({
                    'success': False,
                    'message': 'Password must be at least 8 characters long'
                }, status=400)
            
            # Check if user already exists
            if User.objects.filter(email=email).exists():
                return JsonResponse({
                    'success': False,
                    'message': 'User with this email already exists'
                }, status=400)
            
            # Validate role
            valid_roles = [choice[0] for choice in User.ROLE_CHOICES]
            if role not in valid_roles:
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid role selected'
                }, status=400)
            
            # Create user
            with transaction.atomic():
                user = User.objects.create_user(
                    username=email,
                    email=email,
                    password=password,
                    full_name=name,
                    role=role,
                    is_active=True
                )
                
                # Create user profile
                UserProfile.objects.create(user=user)
                
                # Auto-login the user
                user = authenticate(request, username=email, password=password)
                login(request, user)
                
                # Log login activity
                LoginActivity.objects.create(
                    user=user,
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    role_used=role
                )
            
            return JsonResponse({
                'success': True,
                'message': 'Account created successfully',
                'redirect_url': self.get_redirect_url(role),
                'user': {
                    'id': user.id,
                    'name': user.full_name,
                    'email': user.email,
                    'role': user.role,
                    'role_display': user.get_role_display_icon()
                }
            })
        
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': 'An error occurred during registration'
            }, status=500)
    
    def get_redirect_url(self, role):
        """Get redirect URL based on user role"""
        role_redirects = {
            'admin': '/admin-dashboard/',
            'hr_manager': '/hr-dashboard/',
            'hr_assistant': '/hr-assistant-dashboard/',
            'employee': '/employee-dashboard/',
            'manager': '/manager-dashboard/',
        }
        return role_redirects.get(role, '/dashboard/')

class LogoutView(View):
    """Handle user logout"""
    
    def get(self, request):
        """Process logout request"""
        logout(request)
        messages.success(request, 'You have been logged out successfully')
        return redirect('auth')

@login_required
def dashboard(request):
    """Main dashboard view"""
    user = request.user
    
    # Get recent login activities
    recent_activities = LoginActivity.objects.filter(user=user).order_by('-login_time')[:5]
    
    context = {
        'user': user,
        'recent_activities': recent_activities,
        'role_display': user.get_role_display_icon(),
        'can_manage_users': user.can_manage_users(),
        'can_view_salaries': user.can_view_salaries(),
    }
    
    # Role-specific dashboard templates
    dashboard_templates = {
        'admin': 'dashboard/admin_dashboard.html',
        'hr_manager': 'dashboard/hr_manager_dashboard.html',
        'hr_assistant': 'dashboard/hr_assistant_dashboard.html',
        'employee': 'dashboard/employee_dashboard.html',
        'manager': 'dashboard/manager_dashboard.html',
    }
    
    template = dashboard_templates.get(user.role, 'dashboard/default_dashboard.html')
    return render(request, template, context)

@login_required
def profile(request):
    """User profile view"""
    user = request.user
    
    try:
        profile = user.userprofile
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=user)
    
    context = {
        'user': user,
        'profile': profile,
        'role_display': user.get_role_display_icon(),
    }
    
    return render(request, 'profile/profile.html', context)

def check_email_availability(request):
    """Check if email is available for registration"""
    email = request.GET.get('email', '').strip().lower()
    
    if not email:
