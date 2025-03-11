from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django.utils import timezone
from django.db import transaction
from .models import User
from .serializers import UserSerializer
from .ldap_utils import LDAPManager
from django.conf import settings

class UserViewSet(viewsets.ModelViewSet):
    """ViewSet para ver y editar instancias de usuario."""
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ['username', 'email', 'department', 'is_ldap_user']
    search_fields = ['username', 'first_name', 'last_name', 'email', 'department']
    ordering_fields = ['username', 'email', 'department', 'last_ldap_sync']

    def perform_create(self, serializer):
        """Crea un nuevo usuario con entrada LDAP si is_ldap_user es True."""
        with transaction.atomic():
            user = serializer.save()
            if user.is_ldap_user:
                self._sync_user_to_ldap(user)

    def perform_update(self, serializer):
        """Actualiza el usuario y sincroniza los cambios con LDAP si is_ldap_user es True."""
        with transaction.atomic():
            user = serializer.save()
            if user.is_ldap_user:
                self._sync_user_to_ldap(user)

    def _sync_user_to_ldap(self, user):
        """Sincroniza los datos del usuario con LDAP"""
        if not user.is_ldap_user:
            return

        ldap = LDAPManager()
        try:
            # Conectar con credenciales de administrador (debe estar configurado en settings)
            if not ldap.connect(settings.LDAP_ADMIN_USERNAME, settings.LDAP_ADMIN_PASSWORD):
                raise Exception('Error al conectar con LDAP usando credenciales de administrador')

            # Preparar atributos del usuario
            attributes = {
                'sAMAccountName': user.username,
                'mail': user.email,
                'givenName': user.first_name,
                'sn': user.last_name,
                'description': user.department,
                'mailQuota': str(user.email_quota),
                'identification': user.identification,
                'serviceInternet': 'enable' if user.service_internet else 'disable',
                'serviceMail': 'enable' if user.service_mail else 'disable'
            }

            # Añadir o modificar usuario en LDAP
            if user.ldap_dn:
                ldap.modify_user(user.ldap_dn, attributes)
            else:
                # Crear nueva entrada LDAP
                new_dn = f'CN={user.username},{settings.LDAP_BASE_DN}'
                ldap.add_user(new_dn, attributes)
                user.ldap_dn = new_dn

            user.last_ldap_sync = timezone.now()
            user.save()

        finally:
            ldap.disconnect()

    @action(detail=True, methods=['post'])
    def sync_ldap(self, request, pk=None):
        """Activa manualmente la sincronización LDAP para un usuario."""
        user = self.get_object()
        if not user.is_ldap_user:
            return Response(
                {"detail": "El usuario no es un usuario LDAP."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            self._sync_user_to_ldap(user)
            return Response({"detail": "Sincronización LDAP exitosa."})
        except Exception as e:
            return Response(
                {"detail": f"Error en la sincronización LDAP: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _sync_user_to_ldap(self, user):
        """Sincroniza los datos del usuario con el servidor LDAP."""
        # TODO: Implementar la lógica real de sincronización LDAP
        # Este es un marcador de posición para la implementación real de la sincronización LDAP
        # server = Server(settings.LDAP_SERVER, get_info=ALL)
        # conn = Connection(server, settings.LDAP_BIND_DN, settings.LDAP_BIND_PASSWORD)
        
        # Actualizar marca de tiempo de última sincronización
        user.last_ldap_sync = timezone.now()
        user.save(update_fields=['last_ldap_sync'])
