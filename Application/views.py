from django.utils import timezone

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

from django.shortcuts import render, redirect
#from django.contrib.auth.models import User
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import User
from django.contrib import messages
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from .models import User
from django.contrib import messages
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from .models import Department
from django.contrib.auth.decorators import login_required

@login_required
def department_list(request):
    departments = Department.objects.all()
    return render(request, 'Application/departments.html', {'departments': departments})

@login_required
def add_department(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')

        if Department.objects.filter(name__iexact=name).exists():
            messages.error(request, 'Department with that name already exists.')
        else:
            Department.objects.create(name=name, description=description)
            messages.success(request, 'Department added successfully.')
        return redirect('department_list')

    return render(request, 'Application/add_department.html')

@login_required
def edit_department(request, pk):
    department = get_object_or_404(Department, pk=pk)

    if request.method == 'POST':
        department.name = request.POST.get('name')
        department.description = request.POST.get('description')
        department.save()
        messages.success(request, 'Department updated successfully.')
        return redirect('department_list')

    return render(request, 'Application/edit_department.html', {'department': department})

@login_required
def delete_department(request, pk):
    department = get_object_or_404(Department, pk=pk)
    department.delete()
    messages.success(request, 'Department deleted successfully.')
    return redirect('department_list')

@login_required
def employee_list(request):
    employees = User.objects.filter(role='employee')
    departments = employees.values_list('department', flat=True).distinct()
    context = {
        'employees': employees,
        'total_employees': employees.count(),
        'departments': departments,
    }
    return render(request, 'Application/employees.html', context)


@login_required
def edit_employee(request, pk):
    employee = get_object_or_404(User, pk=pk, role='employee')

    if request.method == 'POST':
        employee.full_name = request.POST.get('full_name')
        employee.phone_number = request.POST.get('phone_number')
        employee.department = request.POST.get('department')
        employee.position = request.POST.get('position')
        employee.save()
        messages.success(request, 'Employee updated successfully.')
        return redirect('employee_list')

    return render(request, 'Application/edit_employee.html', {'employee': employee})

@login_required
def add_employee(request):
    if request.method == 'POST':
        full_name = request.POST.get('full_name')
        email = request.POST.get('email')
        phone_number = request.POST.get('phone_number')
        department = request.POST.get('department')
        position = request.POST.get('position')
        password = request.POST.get('password')

        if not all([full_name, email, department, position, password]):
            messages.error(request, 'All required fields must be filled.')
            return redirect('add_employee')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'A user with that email already exists.')
            return redirect('add_employee')

        User.objects.create(
            username=email,
            email=email,
            full_name=full_name,
            phone_number=phone_number,
            department=department,
            position=position,
            role='employee',
            hire_date=timezone.now().date(),
            password=make_password(password),  # hashed manually since we're not using create_user()
        )

        messages.success(request, 'Employee added successfully.')
        return redirect('employee_list')

    return render(request, 'Application/add_employee.html')

@login_required
def profile_view(request):
    return render(request, 'Application/profile.html', {'user_obj': request.user})

@login_required
def update_profile(request):
    if request.method == 'POST':
        user = request.user
        user.full_name = request.POST.get('full_name')
        user.phone_number = request.POST.get('phone_number')
        user.department = request.POST.get('department')
        user.position = request.POST.get('position')
        user.save()
        messages.success(request, 'Profile updated successfully.')
        return redirect('profile')
    return HttpResponse("Invalid request", status=400)

@csrf_exempt  # Only use this if CSRF token is not included in your form!
def signup_view(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        role = request.POST.get('role')
        department = request.POST.get('department', '')  
        # Basic validation
        if not all([name, email, password, confirm_password, role]):
            return HttpResponse("All fields are required", status=400)

        if password != confirm_password:
            return HttpResponse("Passwords do not match", status=400)

        if User.objects.filter(username=email).exists():
            return HttpResponse("User with this email already exists", status=400)

        # Create user
        user = User.objects.create_user(
            username=email,
            email=email,
            password=password,
            first_name=name,
           role=role,
            department=department,
            hire_date=timezone.now(),
        )

        # You can later link the `role` to a Profile model if needed
        return redirect('dashboard')  # or wherever you want to redirect after success

    return HttpResponse("Invalid request", status=400)
@csrf_exempt  # Optional if you're not using {% csrf_token %}
def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        if not all([email, password]):
            return HttpResponse("Email and password are required", status=400)

        user = authenticate(request, username=email, password=password)

        if user is not None:
            login(request, user)
            return redirect('dashboard')  # Redirect to homepage/dashboard
        else:
            return HttpResponse("Invalid credentials", status=401)

    return HttpResponse("Invalid request", status=400)

def login_page(request):

    return render(request, 'Application/auth.html')

def index(request):

    return render(request, 'Application/index.html')

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
        return render(request, 'Application/auth.html', context)

class LoginView(View):
    """Handle user login"""
    
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)


from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from datetime import datetime
from .models import User, LeaveApplication, Department

@login_required
def dashboard_view(request):
    user = request.user
    context = {}

    # For monthly analytics
    current_month = datetime.now().month
    current_year = datetime.now().year

    # Common data for all
    leaves_this_month = LeaveApplication.objects.filter(
        start_date__month=current_month,
        start_date__year=current_year
    )

    if user.role in ['admin', 'hr_manager', 'hr_assistant']:
        # Admin / HR Dashboard

        context['total_employees'] = User.objects.filter(role='employee').count()
        context['total_hods'] = User.objects.filter(role='manager').count()
        context['total_releavers'] = LeaveApplication.objects.filter(releaver_approved=True).values('releaver').distinct().count()

        context['processed_leaves'] = LeaveApplication.objects.filter(
            final_status__in=['approved', 'rejected']
        ).count()

        context['pending_leaves'] = LeaveApplication.objects.filter(
            final_status='pending'
        ).count()

        context['approved_leaves'] = LeaveApplication.objects.filter(
            final_status='approved'
        ).count()

        context['leaves_this_month'] = leaves_this_month.count()
        context['leaves_per_department'] = User.objects.filter(role='employee') \
          .values('department') \
          .annotate(leave_count=Count('leave_applications')) \
          .order_by('department')

        return render(request, 'Application/admin_dashboard.html', context)

    elif user.role == 'employee':
        # Employee Dashboard

        context['department'] = user.department
        context['my_leaves'] = LeaveApplication.objects.filter(applicant=user)
        context['current_requests'] = context['my_leaves'].filter(final_status='pending')
        context['past_leaves'] = context['my_leaves'].filter(final_status='approved')
        context['reliever_for'] = LeaveApplication.objects.filter(releaver=user)

        # Progress: e.g. leave still in process
        context['in_progress'] = context['current_requests'].filter(
            Q(releaver_approved=False) | Q(hod_approved=False) | Q(admin_approved=False)
        )

        return render(request, 'Application/employee_dashboard.html', context)

    elif user.role == 'manager':
        # HOD Dashboard

        # Employees under this HOD's department
        hod_department = Department.objects.filter(head=user).first()
        employees_under_hod = User.objects.filter(department=hod_department.name)

        context['department'] = hod_department
        context['employees'] = employees_under_hod
        context['total_employees'] = employees_under_hod.count()

        # Leave requests by people in the department
        context['leave_requests'] = LeaveApplication.objects.filter(applicant__in=employees_under_hod)

        context['pending_leaves'] = context['leave_requests'].filter(final_status='pending').count()
        context['approved_leaves'] = context['leave_requests'].filter(final_status='approved').count()
        context['rejected_leaves'] = context['leave_requests'].filter(final_status='rejected').count()
        context['leaves_this_month'] = context['leave_requests'].filter(start_date__month=current_month).count()

        return render(request, 'Application/hod_dashboard.html', context)

    else:
        return render(request, 'Application/unknown_role.html')


    
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

'''class SignupView(View):
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


from django.views import View
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import json

@method_decorator(csrf_exempt, name='dispatch')
class SignupView(View):
    def post(self, request):
        try:
            if request.content_type == 'application/json':
                data = json.loads(request.body)
            else:
                data = request.POST

            username = data.get('username')
            email = data.get('email')
            password = data.get('password')

            if not all([username, email, password]):
                return JsonResponse({'error': 'Missing fields'}, status=400)

            if User.objects.filter(username=username).exists():
                return JsonResponse({'error': 'Username already taken'}, status=400)

            user = User.objects.create_user(username=username, email=email, password=password)
            return JsonResponse({'message': 'Signup successful'}, status=201)

        except Exception as e:
            print(e)
            return JsonResponse({'error': str(e)}, status=400)
'''
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
'''
def check_email_availability(request):
    """Check if email is available for registration"""
    email = request.GET.get('email', '').strip().lower()
    
    if not email:
'''
