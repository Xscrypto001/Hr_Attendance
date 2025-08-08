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



from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import LeaveApplication, User
from django.contrib import messages

# Level 1: Employee applies
@login_required
def apply_leave(request):
    if request.user.role != 'employee':
        return redirect('dashboard')

    if request.method == 'POST':
        reliever_id = request.POST.get('reliever')
        start_date = request.POST.get('start_date')
        end_date = request.POST.get('end_date')
        reason = request.POST.get('reason')

        reliever = User.objects.get(id=reliever_id)
        LeaveApplication.objects.create(
            applicant=request.user,
            releaver=reliever,
            start_date=start_date,
            end_date=end_date,
            reason=reason
        )
        messages.success(request, "Leave application submitted to reliever.")
        return redirect('dashboard')

    employees = User.objects.filter(role='employee').exclude(id=request.user.id)
    return render(request, 'Application/apply_leave.html', {'employees': employees})


# Level 2: Reliever approval
@login_required
def reliever_requests(request):
    if request.user.role != 'employee':
        return redirect('dashboard')

    requests = LeaveApplication.objects.filter(releaver=request.user, releaver_approved=False)
    if request.method == 'POST':
        leave_id = request.POST.get('leave_id')
        action = request.POST.get('action')
        leave = get_object_or_404(LeaveApplication, id=leave_id, releaver=request.user)

        if action == 'approve':
            leave.releaver_approved = True
            leave.save()
            messages.success(request, "Leave approved and sent to HOD.")
        elif action == 'reject':
            leave.final_status = 'rejected'
            leave.save()
            messages.warning(request, "Leave rejected.")
        return redirect('reliever_requests')

    return render(request, 'Application/reliever_requests.html', {'requests': requests})


# Level 3: HOD approval
@login_required
def hod_approvals(request):
    if request.user.role != 'hod':
        return redirect('dashboard')

    dept = request.user.department
    applications = LeaveApplication.objects.filter(
        applicant__department=dept,
        releaver_approved=True,
        hod_approved=False
    )

    if request.method == 'POST':
        leave_id = request.POST.get('leave_id')
        action = request.POST.get('action')
        leave = get_object_or_404(LeaveApplication, id=leave_id)

        if action == 'approve':
            leave.hod_approved = True
            leave.save()
            messages.success(request, "Leave sent to Admin for final approval.")
        elif action == 'reject':
            leave.final_status = 'rejected'
            leave.save()
            messages.warning(request, "Leave rejected.")
        return redirect('hod_approvals')

    return render(request, 'Application/hod_approvals.html', {'applications': applications})


# Level 4: Admin approval
@login_required
def admin_approvals(request):
    if request.user.role not in ['admin', 'hr_manager', 'hr_assistant']:
        return redirect('dashboard')

    applications = LeaveApplication.objects.filter(
       
        final_status='pending'
    )

    if request.method == 'POST':
        leave_id = request.POST.get('leave_id')
        action = request.POST.get('action')
        leave = get_object_or_404(LeaveApplication, id=leave_id)

        if action == 'approve':
            leave.admin_approved = True
            leave.final_status = 'approved'
            leave.save()
            messages.success(request, "Leave fully approved.")
        elif action == 'reject':
            leave.final_status = 'rejected'
            leave.save()
            messages.warning(request, "Leave rejected.")
        return redirect('admin_approvals')

    return render(request, 'Application/admin_approvals.html', {'applications': applications})



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

    return render(request, 'Application/add_departments.html')

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

from django.contrib.auth import update_session_auth_hash

@login_required
def update_profile(request):
    if request.method == 'POST':
        user = request.user

        # Update fields
        user.full_name = request.POST.get('full_name')
        user.phone_number = request.POST.get('phone_number')
        user.department = request.POST.get('department')
        user.position = request.POST.get('position')

        # Handle password change
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password or confirm_password:
            if new_password != confirm_password:
                messages.error(request, 'Passwords do not match.')
                return redirect('profile')
            elif len(new_password) < 6:
                messages.error(request, 'Password must be at least 6 characters.')
                return redirect('profile')
            else:
                user.set_password(new_password)
                update_session_auth_hash(request, user)  # keep user logged in

        user.save()
        messages.success(request, 'Profile updated successfully.')
        return redirect('profile')

    return HttpResponse("Invalid request", status=400)


def update(request):
   return render(request, 'Application/update.html')


'''
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
'''

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import HttpResponse

@login_required
def profile_view(request):
    departments = [
        "Finance", "IT Support", "Human Resources", "Marketing", "Sales",
        "Operations", "Procurement", "Legal", "Customer Service"
    ]
    return render(request, 'Application/profile.html', {
        'user_obj': request.user,
        'departments': departments
    })
'''
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
'''
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
        user_reg = authenticate(request, username=email, password=password)
        login(request, user_reg)

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
        context['leave_requests'] = LeaveApplication.objects.all()
        context['leaves_this_month'] = leaves_this_month.count()
        context['leaves_per_department'] = User.objects.filter(role='employee') \
          .values('department') \
          .annotate(leave_count=Count('leave_applications')) \
          .order_by('department')

        return render(request, 'Application/admin_dashboard.html', context)

    elif user.role == 'employee':
    leave_types = LeaveType.objects.all()
    leave_balances = []

    for leave_type in leave_types:
        approved_leaves = LeaveApplication.objects.filter(
            applicant=user,
            leave_type=leave_type,
            final_status='approved'
        )

        used_days = sum(
            (leave.end_date - leave.start_date).days + 1
            for leave in approved_leaves
        )

        max_allowed = leave_type.max_days  # assuming each LeaveType has a max_days field
        remaining_days = max_allowed - used_days if max_allowed > used_days else 0
        percentage = round((used_days / max_allowed) * 100) if max_allowed > 0 else 0

        leave_balances.append({
            'type': leave_type.name,
            'used': used_days,
            'remaining': remaining_days,
            'allowed': max_allowed,
            'percentage': percentage
        })


    context['leave_balances'] = leave_balances

        # Progress: e.g. leave still in process
        context['in_progress'] = context['current_requests'].filter(
            Q(releaver_approved=False) | Q(hod_approved=False) | Q(admin_approved=False)
        )

        return render(request, 'Application/employee_dashboard.html', context)

    elif user.role == 'hod':
        # HOD Dashboard

        # Employees under this HOD's department

        hod_department = user.department
        employees_under_hod = []

        if hod_department:
            employees_under_hod = User.objects.filter(department=hod_department)
        else:
            messages.warning(request, "You are not assigned as HOD of any department.")


        
        context['department'] = hod_department
        context['employees'] = employees_under_hod
        context['total_employees'] = len(employees_under_hod)
        
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


'''# views.py
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from datetime import date
from .models import LeaveApplication

@login_required
def leave_progress_view(request):
    user = request.user
    approved_leaves = LeaveApplication.objects.filter(
        applicant=user,
        final_status='approved'
    )

    total_taken = sum([leave.total_days() for leave in approved_leaves])
    max_allowed = 60
    percentage = round((total_taken / max_allowed) * 100) if max_allowed > 0 else 0

    context = {
        'total_taken': total_taken,
        'max_allowed': max_allowed,
        'percentage': percentage
    }

    return render(request, 'leaves/progress_doughnut.html', context)





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
