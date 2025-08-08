
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

class User(AbstractUser):

    
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        
        ('employee', 'Employee'),
        ('hod', 'Hod'),
    ]
    
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    full_name = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    date_joined = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    
    
    # Department and employee details
    department = models.CharField(max_length=100, blank=True, null=True)
    employee_id = models.CharField(max_length=20, unique=True, blank=True, null=True)
    hire_date = models.DateField(blank=True, null=True)
    position = models.CharField(max_length=100, blank=True, null=True)
    salary = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    manager = models.ForeignKey('self', on_delete=models.SET_NULL, blank=True, null=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'role', 'full_name']
    
    def __str__(self):
        return f"{self.full_name} ({self.email}) - {self.get_role_display()}"
    
    def get_role_display_icon(self):
        """Return role with appropriate icon"""
        role_icons = {
            'admin': '👑',
            'hr_manager': '🏢',
            'hr_assistant': '👥',
            'employee': '👤',
            'manager': '📊',
        }
        return f"{role_icons.get(self.role, '👤')} {self.get_role_display()}"
    
    def can_manage_users(self):
        """Check if user can manage other users"""
        return self.role in ['admin', 'hr_manager']
    
    def can_view_salaries(self):
        """Check if user can view salary information"""
        return self.role in ['admin', 'hr_manager']
    
    def get_subordinates(self):
        """Get all users that report to this user"""
        return User.objects.filter(manager=self)

class Department(models.Model):
    """Department model"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    head = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='headed_departments')
    created_date = models.DateTimeField(default=timezone.now)
    budget = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)
    
    def __str__(self):
        return self.name
    
    def get_employees(self):
        """Get all employees in this department"""
        return User.objects.filter(department=self.name)

class UserProfile(models.Model):
    """Extended user profile information"""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField(max_length=500, blank=True)
    birth_date = models.DateField(blank=True, null=True)
    address = models.TextField(blank=True)
    emergency_contact_name = models.CharField(max_length=100, blank=True)
    emergency_contact_phone = models.CharField(max_length=15, blank=True)
    skills = models.TextField(blank=True, help_text="Comma-separated list of skills")
    certifications = models.TextField(blank=True)
    education = models.TextField(blank=True)
    
    def __str__(self):
        return f"{self.user.full_name}'s Profile"

class LoginActivity(models.Model):
    """Track user login activities"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    login_time = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    role_used = models.CharField(max_length=20)
    
    def __str__(self):
        return f"{self.user.email} - {self.login_time}"
    
    class Meta:
        ordering = ['-login_time']




class LeaveType(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    max_days = models.PositiveIntegerField(default=60)  # default max days per year
    REASON_CHOICES = [
    ('Vacation', 'Vacation'),
    ('Sick', 'Sick'),
    ('Maternity', 'Maternity'),
    ('Bereavement', 'Bereavement'),
    ('Unpaid', 'Unpaid'),
    ('Educational', 'Educational'),
]

    reason = models.CharField(max_length=20, choices=REASON_CHOICES ,null=True, default='Vacation leave')
    def __str__(self):
        return self.name



class LeaveApplication(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('rejected', 'Rejected'),
        ('approved', 'Approved'),
        ('cancelled', 'Cancelled'),
    ]
    REASON_CHOICE = [
    ('Vacation', 'Vacation'),
    ('Sick', 'Sick'),
    ('Maternity', 'Maternity'),
    ('Bereavement', 'Bereavement'),
    ('Unpaid', 'Unpaid'),
    ('Educational', 'Educational'),
]



    applicant = models.ForeignKey(User, related_name='leave_applications', on_delete=models.CASCADE)
    releaver = models.ForeignKey(User, related_name='releaver_requests', on_delete=models.SET_NULL, null=True)
    leave_type = models.CharField(max_length=20, choices=REASON_CHOICE ,null=True, default='Casual leave')
    
    start_date = models.DateField()
    end_date = models.DateField()
    reason = models.TextField()

    releaver_approved = models.BooleanField(default=False)
    hod_approved = models.BooleanField(default=False)
    admin_approved = models.BooleanField(default=False)

    final_status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    submitted_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def total_days(self):
        return (self.end_date - self.start_date).days + 1

    def __str__(self):
        return f"{self.applicant.full_name} - {self.leave_type} from {self.start_date} to {self.end_date}"


class LeaveApprovalLog(models.Model):
    leave = models.ForeignKey(LeaveApplication, related_name='approval_logs', on_delete=models.CASCADE)
    approver = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    role = models.CharField(max_length=20)  # 'releaver', 'hod', 'admin'
    decision = models.CharField(max_length=20, choices=[('approved', 'Approved'), ('rejected', 'Rejected')])
    comments = models.TextField(blank=True)
    date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.role} - {self.approver.full_name} - {self.decision}"
