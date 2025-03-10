from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_in, user_logged_out
from .models import LDAPUser, ActivityLog

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    ActivityLog.objects.create(
        user=user if isinstance(user, LDAPUser) else None,
        activity_type='LOGIN',
        description=f'Inicio de sesión exitoso - Usuario: {user.username}',
        ip_address=get_client_ip(request),
        target_user=user.username
    )

@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    if user:
        ActivityLog.objects.create(
            user=user if isinstance(user, LDAPUser) else None,
            activity_type='LOGOUT',
            description=f'Cierre de sesión - Usuario: {user.username}',
            ip_address=get_client_ip(request),
            target_user=user.username
        )

@receiver(post_save, sender=LDAPUser)
def log_user_changes(sender, instance, created, **kwargs):
    if created:
        ActivityLog.objects.create(
            user=None,  # El sistema es el que crea el usuario inicialmente
            activity_type='CREATE',
            description=f'Usuario creado: {instance.username}',
            target_user=instance.username
        )
    else:
        ActivityLog.objects.create(
            user=None,
            activity_type='UPDATE',
            description=f'Usuario actualizado: {instance.username}',
            target_user=instance.username
        )

@receiver(post_delete, sender=LDAPUser)
def log_user_deletion(sender, instance, **kwargs):
    ActivityLog.objects.create(
        user=None,
        activity_type='DELETE',
        description=f'Usuario eliminado: {instance.username}',
        target_user=instance.username
    )

@receiver(post_save, sender=LDAPUser)
def log_user_changes(sender, instance, created, **kwargs):
    if created:
        ActivityLog.objects.create(
            user=None,  # El sistema es el que crea el usuario inicialmente
            activity_type='CREATE',
            description=f'Usuario creado: {instance.username}',
            target_user=instance.username
        )
    else:
        ActivityLog.objects.create(
            user=None,
            activity_type='UPDATE',
            description=f'Usuario actualizado: {instance.username}',
            target_user=instance.username
        )
