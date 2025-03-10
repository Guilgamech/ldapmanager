from django.db import models
from django.contrib.auth.models import AbstractUser
from ldap3 import Server, Connection, SUBTREE
from django.conf import settings
from datetime import datetime

class LDAPUser(AbstractUser):
    """Modelo extendido de usuario para integración con LDAP"""
    email = models.EmailField(unique=True)
    mail_quota = models.IntegerField(default=settings.DEFAULT_MAIL_QUOTA)
    last_login_attempt = models.DateTimeField(null=True, blank=True)
    login_attempts = models.IntegerField(default=0)

    # Add related_name to avoid clashes with auth.User
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        help_text='The groups this user belongs to.',
        related_name='ldap_user_set',
        related_query_name='ldap_user'
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name='ldap_user_set',
        related_query_name='ldap_user'
    )

    class Meta:
        verbose_name = 'Usuario LDAP'
        verbose_name_plural = 'Usuarios LDAP'

    @classmethod
    def authenticate(cls, username, password):
        """Autenticar usuario contra el servidor LDAP"""
        try:
            server = Server(settings.LDAP_SERVER_URI)
            # Intentar conexión con las credenciales del usuario
            with Connection(
                server,
                user=f'uid={username},{settings.LDAP_BASE_DN}',
                password=password
            ) as conn:
                if conn.bind():
                    # Buscar información del usuario
                    conn.search(
                        settings.LDAP_BASE_DN,
                        f'(uid={username})',
                        SUBTREE,
                        attributes=['mail', 'mailQuota']
                    )
                    if conn.entries:
                        user_data = conn.entries[0]
                        user, created = cls.objects.get_or_create(
                            username=username,
                            defaults={
                                'email': user_data.mail.value,
                                'mail_quota': user_data.mailQuota.value
                            }
                        )
                        user.last_login = datetime.now()
                        user.login_attempts = 0
                        user.save()
                        return user
            return None
        except Exception as e:
            print(f'Error de autenticación LDAP: {str(e)}')
            return None

class ActivityLog(models.Model):
    """Registro de actividades del sistema"""
    ACTIVITY_TYPES = [
        ('CREATE', 'Crear'),
        ('UPDATE', 'Actualizar'),
        ('DELETE', 'Eliminar'),
        ('LOGIN', 'Inicio de sesión'),
        ('LOGOUT', 'Cierre de sesión'),
    ]

    user = models.ForeignKey(LDAPUser, on_delete=models.SET_NULL, null=True)
    activity_type = models.CharField(max_length=10, choices=ACTIVITY_TYPES)
    description = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True)
    target_user = models.CharField(max_length=150, blank=True)

    class Meta:
        verbose_name = 'Registro de actividad'
        verbose_name_plural = 'Registros de actividades'
        ordering = ['-timestamp']

    def __str__(self):
        return f'{self.get_activity_type_display()} - {self.user} - {self.timestamp}'
