

from .views import LoginView,LogoutView
from django.urls import path
from . import views

urlpatterns = [
path('', views.index, name='index'),
path('employees/add/', views.add_employee, name='add_employee'),
path('employees/', views.employee_list, name='employee_list'),
    path('employees/<int:pk>/edit/', views.edit_employee, name='edit_employee'),

path('logout/', LogoutView.as_view(), name='logout'),
     path('signup/', views.signup_view, name='register'),
    path('auth/', views.login_page, name='auth'),
    path('signin/', views.login_view, name='login'),
path('dashboard/', views.dashboard_view, name='dashboard'),
path('profile/', views.profile_view, name='profile'),
    path('profile/update/', views.update_profile, name='update_profile'),
#    path('signu/', SignupView.as_view(), name='signup'),
]
