from django.db import models
from django.contrib.auth.models import AbstractUser
from simple_history.models import HistoricalRecords

class User(AbstractUser):
    """Custom user model for LDAP management"""
    email_quota = models.IntegerField(default=1024, help_text='Email quota in MB')
    ldap_dn = models.CharField(max_length=255, unique=True, help_text='LDAP Distinguished Name')
    department = models.CharField(max_length=100, blank=True)
    employee_number = models.CharField(max_length=50, blank=True)
    identification = models.CharField(max_length=11, unique=True, help_text='Identification number (CI/DNI)')
    service_internet = models.BooleanField(default=True, help_text='Internet service status')
    service_mail = models.BooleanField(default=True, help_text='Email service status')
    is_ldap_user = models.BooleanField(default=True)
    last_ldap_sync = models.DateTimeField(null=True, blank=True)
    history = HistoricalRecords()

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['username']

    def __str__(self):
        return self.username
