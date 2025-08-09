from django.urls import path
from django.contrib.auth.views import LogoutView
from . import views

urlpatterns = [
    # Auth
    path('signup/', views.SignupView.as_view(), name='register'),
    path('signin/', views.LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),

    # Leave management
    path('leave/apply/', views.apply_leave, name='apply_leave'),
    path('leave/reliever/', views.reliever_requests, name='reliever_requests'),
    path('leave/hod/', views.hod_approvals, name='hod_approvals'),
    path('leave/admin/', views.admin_approvals, name='admin_approvals'),

    # Departments
    path('departments/', views.department_list, name='department_list'),
    path('departments/add/', views.add_department, name='add_department'),
    path('departments/<int:pk>/edit/', views.edit_department, name='edit_department'),
    path('departments/<int:pk>/delete/', views.delete_department, name='delete_department'),

    # Employees
    path('employees/', views.employee_list, name='employee_list'),
    path('employees/add/', views.add_employee, name='add_employee'),
    path('employees/<int:pk>/edit/', views.edit_employee, name='edit_employee'),

    # Profile
    path('profile/', views.profile_view, name='profile'),
    path('profile/update/', views.update_profile, name='update_profile'),

    # Dashboard and home
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('', views.AuthView.as_view(), name='auth'),  # homepage/login page
]
