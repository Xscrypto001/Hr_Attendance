

from .views import LoginView,LogoutView
from django.urls import path
from . import views

urlpatterns = [
path('', views.index, name='index'),
path('logout/', LogoutView.as_view(), name='logout'),
     path('signup/', views.signup_view, name='register'),
    path('auth/', views.login_page, name='auth'),
    path('signin/', views.login_view, name='login'),
#    path('signu/', SignupView.as_view(), name='signup'),
]
