from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name ="home"),
    path('login/', views.login_user, name ='login'),
    path('logout/', views.logout_user, name='logout'),
    path('register/', views.register_user, name='register'),
    path('edit_profile/', views.edit_profile, name='edit_profile'),
    path('change_password/', views.change_password, name='change_password'),
    path('passgen/', views.password_generator_view, name='passgen'),
    path('check_strength/', views.check_password_strength, name='check_strength'),
    path('password_history/', views.password_history, name='password_history'),  # New URL for password history
    path('test_encryption/', views.test_encryption, name='test_encryption'),  # Test encryption/decryption
    path('check_password_strength/', views.check_password_strength, name='check_password_strength'),
    path("analyze-password/", views.analyze_password, name="analyze_password"),
    # Other URL patterns
    # Other URL patterns
    
]

