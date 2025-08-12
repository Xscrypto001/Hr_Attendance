# views.py
from django.utils import timezone
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views.generic import View
from django.db import transaction
from django.contrib.auth.hashers import make_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.db.models import Count, Q
from datetime import datetime
import json

from .models import (
    User,
    LoginActivity,
    UserProfile,
    Department,
    LeaveApplication,
    LeaveType,
)

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
    def get(self, request):
        if request.user.is_authenticated:
            return redirect('dashboard')
        context = {'roles': User.ROLE_CHOICES}
        return render(request, 'Application/auth.html', context)


class LoginView(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        try:
            if request.content_type == 'application/json':
                data = json.loads(request.body)
            else:
                data = request.POST

            email = data.get('email', '').strip().lower()
            password = data.get('password', '')
            role = data.get('role', '')

            if not email or not password or not role:
                return JsonResponse({'success': False, 'message': 'All fields are required'}, status=400)

            try:
                validate_email(email)
            except ValidationError:
                return JsonResponse({'success': False, 'message': 'Invalid email format'}, status=400)

            try:
                user_obj = User.objects.get(email=email, role=role)
            except User.DoesNotExist:
                return JsonResponse({'success': False, 'message': 'Invalid credentials or role'}, status=401)

            user = authenticate(request, username=email, password=password)
            if user and user.is_active:
                if user.role != role:
                    return JsonResponse({'success': False, 'message': 'Invalid role for this account'}, status=401)

                login(request, user)
                LoginActivity.objects.create(
                    user=user,
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    role_used=role,
                )
                return JsonResponse({
                    'success': True,
                    'message': 'Login successful',
                    'redirect_url': self.get_redirect_url(user.role),
                    'user': {
                        'id': user.id,
                        'name': user.full_name,
                        'email': user.email,
                        'role': user.role,
                    }
                })
            else:
                return JsonResponse({'success': False, 'message': 'Invalid credentials'}, status=401)

        except Exception:
            return JsonResponse({'success': False, 'message': 'An error occurred during login'}, status=500)

    def get_redirect_url(self, role):
        role_redirects = {
            'admin': '/admin-dashboard/',
            'hr_manager': '/hr-dashboard/',
            'hr_assistant': '/hr-assistant-dashboard/',
            'employee': '/employee-dashboard/',
            'manager': '/manager-dashboard/',
        }
        return role_redirects.get(role, '/dashboard/')

def index(request):


   return render(request, "Application/index.html")
class SignupView(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        try:
            if request.content_type == 'application/json':
                data = json.loads(request.body)
            else:
                data = request.POST

            name = data.get('name', '').strip()
            email = data.get('email', '').strip().lower()
            password = data.get('password', '')
            confirm_password = data.get('confirm_password', '')
            role = data.get('role', '')

            if not all([name, email, password, confirm_password, role]):
                return  redirect('index')

            try:
                validate_email(email)
            except ValidationError:
                return JsonResponse({'success': False, 'message': 'Invalid email format'}, status=400)

            if password != confirm_password:
                return JsonResponse({'success': False, 'message': 'Passwords do not match'}, status=400)

            if len(password) < 8:
                return JsonResponse({'success': False, 'message': 'Password must be at least 8 characters long'}, status=400)

            if User.objects.filter(email=email).exists():
                return JsonResponse({'success': False, 'message': 'User with this email already exists'}, status=400)

            valid_roles = [choice[0] for choice in User.ROLE_CHOICES]
            if role not in valid_roles:
                return JsonResponse({'success': False, 'message': 'Invalid role selected'}, status=400)

            with transaction.atomic():
                user = User.objects.create_user(
                    username=email,
                    email=email,
                    password=password,
                    full_name=name,
                    role=role,
                    is_active=True
                )
                UserProfile.objects.create(user=user)

                user = authenticate(request, username=email, password=password)
                login(request, user)
                LoginActivity.objects.create(
                    user=user,
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    role_used=role,
                )

            return redirect('index')
        except Exception:
            return JsonResponse({'success': False, 'message': 'An error occurred during registration'}, status=500)


@login_required
def logout_view(request):
    logout(request)
    messages.success(request, 'You have been logged out successfully')
    return redirect('auth')


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
            leave_type=reason,
            start_date=start_date,
            end_date=end_date,
            reason=reason,
        )
        messages.success(request, "Leave application submitted to reliever.")
        return redirect('dashboard')

    employees = User.objects.filter(role='employee').exclude(id=request.user.id)
    return render(request, 'Application/apply_leave.html', {'employees': employees})


@login_required
def reliever_requests(request):
    if request.userole != 'employee':
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


@login_required
def hod_approvals(request):
    if request.user.role != 'hod':
        return redirect('dashboard')

    dept = request.user.department
    applications = LeaveApplication.objects.filter(applicant__department=dept, releaver_approved=True, hod_approved=False)

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


@login_required
def admin_approvals(request):
    if request.user.role not in ['admin', 'hr_manager', 'hr_assistant']:
        return redirect('dashboard')

    applications = LeaveApplication.objects.filter(final_status='pending')

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
            password=make_password(password),
        )

        messages.success(request, 'Employee added successfully.')
        return redirect('employee_list')

    return render(request, 'Application/add_employee.html')


@login_required
def update_profile(request):
    if request.method == 'POST':
        user = request.user
        user.full_name = request.POST.get('full_name')
        user.phone_number = request.POST.get('phone_number')
        user.department = request.POST.get('department')
        user.position = request.POST.get('position')

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
                update_session_auth_hash(request, user)

        user.save()
        messages.success(request, 'Profile updated successfully.')
        return redirect('profile')

    return HttpResponse("Invalid request", status=400)


@login_required
def profile_view(request):
    departments = [
        "Finance", "IT Support", "Human Resources", "Marketing", "Sales",
        "Operations", "Procurement", "Legal", "Customer Service"
    ]
    return render(request, 'Application/profile.html', {'user_obj': request.user, 'departments': departments})


@login_required
def dashboard_view(request):
    user = request.user
    context = {}

    current_month = datetime.now().month
    current_year = datetime.now().year

    leaves_this_month = LeaveApplication.objects.filter(
        start_date__month=current_month,
        start_date__year=current_year
    )

    if user.role in ['admin', 'hr_manager', 'hr_assistant']:
        context['total_employees'] = User.objects.filter(role='employee').count()
        context['total_hods'] = User.objects.filter(role='manager').count()
        context['total_releavers'] = LeaveApplication.objects.filter(releaver_approved=True).values('releaver').distinct().count()
        context['processed_leaves'] = LeaveApplication.objects.filter(final_status__in=['approved', 'rejected']).count()
        context['pending_leaves'] = LeaveApplication.objects.filter(final_status='pending').count()
        context['approved_leaves'] = LeaveApplication.objects.filter(final_status='approved').count()
        context['leave_requests'] = LeaveApplication.objects.all()
        context['leaves_this_month'] = leaves_this_month.count()
        context['leaves_per_department'] = User.objects.filter(role='employee') \
            .values('department') \
            .annotate(leave_count=Count('leave_applications')) \
            .order_by('department')

        return render(request, 'Application/admin_dashboard.html', context)

    elif user.role == 'employee':
        leave_types1 = [
            ("Vacaton", "#ec4899"),
            ("Maternity ", "#22c55e"),
            ("Unpaid", "#facc15"),
            ("Educational", "#3b82f6")
         ]

        leave_data = []
        circumference = 283  # circle circumference for SVG

        for leave_type, color in leave_types1:
            leaves = LeaveApplication.objects.filter(
               applicant=request.user,
               leave_type__icontains=leave_type,
               final_status="approved"
          )

        total_days_taken = sum([leave.total_days() for leave in leaves])

        max_days = {
            "Vacaton": 10,
            "Educational": 15,
            "Unpaid": 15,
            "Educational": 27
        }.get(leave_type, 0)

        balance = max_days - total_days_taken
        if balance < 0:
            balance = 0

        # Compute stroke offset here
        if max_days > 0:
            stroke_offset = circumference - (circumference * (balance / max_days))
        else:
            stroke_offset = circumference

        leave_data.append({
            "name": f"{leave_type} Leave" if leave_type != "Floater" else "Floater Holiday",
            "balance": balance,
            "color": color,
            "max_days": max_days,
            "stroke_offset": stroke_offset
         })






        '''leave_types = [
           ("Vacaton", "#ec4899"),
           ("Maternity ", "#22c55e"),
            ("Unpaid", "#facc15"),
            ("Educational", "#3b82f6")
         ]

        leave_data = []
        circumference = 283  # circle circumference for SVG

        for leave_type, color in leave_types:
            leaves = LeaveApplication.objects.filter(
               applicant=request.user,
               leave_type__icontains=leave_type,
               final_status="approved"
             )

        total_days_taken = sum([leave.total_days() for leave in leaves])

        max_days = {
            "Vacaton": 10,
            "Educational": 15,
            "Unpaid": 15,
            "Educational": 27
        }.get(leave_type, 0)

        balance = max_days - total_days_taken
        if balance < 0:
            balance = 0

        # Compute stroke offset here
        if max_days > 0:
            stroke_offset = circumference - (circumference * (balance / max_days))
        else:
            stroke_offset = circumference

        leave_data.append({
            "name": f"{leave_type} Leave" if leave_type != "Floater" else "Floater Holiday",
            "balance": balance,
            "color": color,
            "max_days": max_days,
            "stroke_offset": stroke_offset
        })'''
        # Compute per-leave-type balances and usage for this employee
        leave_types = LeaveType.objects.all()
        leave_balances = []

        # All leaves by this user (useful in template)
        my_leaves = LeaveApplication.objects.filter(applicant=user)
        current_requests = my_leaves.filter(final_status='pending')

        for lt in leave_types:
            # If LeaveApplication.leave_type is a string storing the name:
            approved_leaves = LeaveApplication.objects.filter(
                applicant=user,
                leave_type=lt.name,
                final_status='approved'
            )

            # If leave_type is stored as a FK in your model, use:
            # approved_leaves = LeaveApplication.objects.filter(applicant=user, leave_type=lt, final_status='approved')

            used_days = sum((l.end_date - l.start_date).days + 1 for l in approved_leaves)
            max_allowed = lt.max_days or 0
            remaining_days = max(0, max_allowed - used_days)
            percentage = round((used_days / max_allowed) * 100) if max_allowed > 0 else 0

            leave_balances.append({
                'type': lt.name,
                'used': used_days,
                'remaining': remaining_days,
                'allowed': max_allowed,
                'percentage': percentage,
            })

        context['department'] = user.department
        context['my_leaves'] = my_leaves
        context['current_requests'] = current_requests
        context['past_leaves'] = my_leaves.filter(final_status='approved')
        context['reliever_for'] = LeaveApplication.objects.filter(releaver=user)
        context['leave_balances'] = leave_balances
        context['in_progress'] = current_requests.filter(Q(releaver_approved=False) | Q(hod_approved=False) | Q(admin_approved=False))
        
        context['leave_data'] = leave_data
        return render(request, 'Application/employee_dashboard.html', context)

    elif user.role == 'hod':
        hod_department = user.department
        employees_under_hod = []
        if hod_department:
            employees_under_hod = User.objects.filter(department=hod_department)
        else:
            messages.warning(request, "You are not assigned as HOD of any department.")

        context['department'] = hod_department
        context['employees'] = employees_under_hod
        context['total_employees'] = len(employees_under_hod)
        context['leave_requests'] = LeaveApplication.objects.filter(applicant__in=employees_under_hod)
        context['pending_leaves'] = context['leave_requests'].filter(final_status='pending').count()
        context['approved_leaves'] = context['leave_requests'].filter(final_status='approved').count()
        context['rejected_leaves'] = context['leave_requests'].filter(final_status='rejected').count()
        context['leaves_this_month'] = context['leave_requests'].filter(start_date__month=current_month).count()

        return render(request, 'Application/hod_dashboard.html', context)

    else:
        return render(request, 'Application/unknown_role.html')
