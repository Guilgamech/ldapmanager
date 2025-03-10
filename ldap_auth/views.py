from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login, logout
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
import json
import base64
from django.conf import settings
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE
from .models import LDAPUser
from .middleware import ldap_auth_required

def get_ldap_connection():
    server = Server(settings.LDAP_SERVER_URI, get_info=ALL)
    conn = Connection(server, settings.LDAP_BIND_DN, settings.LDAP_BIND_PASSWORD, auto_bind=True)
    return conn

@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def login_view(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Formato de datos inválido'}, status=400)

    username = data.get('username')
    password = data.get('password')

    # Validar campos requeridos
    if not username or not password:
        return JsonResponse({'error': 'El nombre de usuario y la contraseña son requeridos'}, status=400)

    # Validar longitud del nombre de usuario
    if len(username) < 3 or len(username) > 50:
        return JsonResponse({'error': 'El nombre de usuario debe tener entre 3 y 50 caracteres'}, status=400)

    # Validar caracteres permitidos en el nombre de usuario
    if not username.isalnum():
        return JsonResponse({'error': 'El nombre de usuario solo puede contener letras y números'}, status=400)
    
    try:
        server = Server(settings.LDAP_SERVER_URI, get_info=ALL)
        user_dn = f'uid={username},{settings.LDAP_BASE_DN}'
        conn = Connection(server, user_dn, password)
        
        if conn.bind():
            # Generar token de autenticación
            auth_token = base64.b64encode(f'{username}:{password}'.encode('utf-8')).decode('utf-8')
            
            # Buscar información adicional del usuario
            conn.search(
                settings.LDAP_BASE_DN,
                f'(uid={username})',
                SUBTREE,
                attributes=['mail', 'cn', 'sn', 'mailQuota']
            )
            
            if conn.entries:
                user_data = conn.entries[0]
                user_info = {
                    'username': username,
                    'name': user_data.cn.value if hasattr(user_data, 'cn') else '',
                    'email': user_data.mail.value if hasattr(user_data, 'mail') else f'{username}@reduc.edu.cu',
                    'mail_quota': user_data.mailQuota.value if hasattr(user_data, 'mailQuota') else settings.DEFAULT_MAIL_QUOTA,
                    'authToken': auth_token
                }
                
                # Crear o actualizar usuario en Django
                user, created = LDAPUser.objects.get_or_create(
                    username=username,
                    defaults={
                        'email': user_info['email'],
                        'first_name': user_info['name'],
                        'mail_quota': user_info['mail_quota']
                    }
                )
                
                if not created:
                    user.email = user_info['email']
                    user.first_name = user_info['name']
                    user.mail_quota = user_info['mail_quota']
                    user.save()
                
                login(request, user)
                return JsonResponse(user_info)
            
            return JsonResponse({'error': 'No se pudo obtener la información del usuario'}, status=500)
        else:
            return JsonResponse({'error': 'Credenciales inválidas'}, status=401)
    except Exception as e:
        error_msg = 'Error de autenticación'
        if 'invalid credentials' in str(e).lower():
            error_msg = 'Credenciales inválidas'
        elif 'connection error' in str(e).lower():
            error_msg = 'Error de conexión con el servidor LDAP'
        return JsonResponse({'error': error_msg}, status=500)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    logout(request)
    return JsonResponse({'message': 'Sesión cerrada exitosamente'})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_list(request):
    try:
        conn = get_ldap_connection()
        search_filter = '(objectClass=inetOrgPerson)'
        attrs = ['uid', 'cn', 'mail']
        
        conn.search(settings.LDAP_BASE_DN, search_filter, SUBTREE, attributes=attrs)
        users = [{'username': entry['uid'].value,
                 'name': entry['cn'].value,
                 'email': entry['mail'].value if 'mail' in entry else ''}
                for entry in conn.entries]
        
        return Response(users)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def user_create(request):
    try:
        data = request.data
        
        # Validar campos requeridos
        required_fields = ['username', 'name', 'lastname', 'password']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return Response(
                {'error': f'Campos requeridos faltantes: {", ".join(missing_fields)}'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validar formato de nombre de usuario
        username = data['username']
        if not username.isalnum() or len(username) < 3 or len(username) > 50:
            return Response(
                {'error': 'El nombre de usuario debe contener solo letras y números, y tener entre 3 y 50 caracteres'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validar contraseña
        password = data['password']
        if len(password) < 8:
            return Response(
                {'error': 'La contraseña debe tener al menos 8 caracteres'},
                status=status.HTTP_400_BAD_REQUEST
            )

        conn = get_ldap_connection()
        
        # Verificar si el usuario ya existe
        search_filter = f'(uid={username})'
        conn.search(settings.LDAP_BASE_DN, search_filter, SUBTREE)
        if conn.entries:
            return Response(
                {'error': 'El nombre de usuario ya existe'},
                status=status.HTTP_409_CONFLICT
            )
        
        # Generar correo electrónico
        email = f'{username}@reduc.edu.cu'
        
        user_dn = f'uid={username},{settings.LDAP_BASE_DN}'
        attrs = {
            'objectClass': settings.LDAP_USER_OBJECT_CLASSES,
            'uid': [username.encode('utf-8')],
            'cn': [data['name'].encode('utf-8')],
            'sn': [data['lastname'].encode('utf-8')],
            'userPassword': [('"' + password + '"').encode('utf-16le')],
            'mail': [email.encode('utf-8')],
            'userPrincipalName': [email.encode('utf-8')],
            'userAccountControl': [str(settings.LDAP_DEFAULT_USER_ACCOUNT_CONTROL).encode('utf-8')]
        }
        
        # Agregar servicios del usuario
        for service, value in settings.LDAP_USER_SERVICES.items():
            attrs[service] = [value.encode('utf-8')]

        # Agregar atributos opcionales
        if 'accountExpires' in data:
            attrs['accountExpires'] = [str(data['accountExpires']).encode('utf-8')]
            
        conn.add(user_dn, settings.LDAP_USER_OBJECT_CLASSES, attrs)
        return Response({'message': 'Usuario creado exitosamente'})
    except Exception as e:
        error_msg = 'Error al crear el usuario'
        if 'already exists' in str(e).lower():
            error_msg = 'El usuario ya existe en el sistema'
        elif 'connection error' in str(e).lower():
            error_msg = 'Error de conexión con el servidor LDAP'
        return Response({'error': error_msg}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_detail(request, username):
    try:
        conn = get_ldap_connection()
        search_filter = f'(uid={username})'
        conn.search(settings.LDAP_BASE_DN, search_filter, SUBTREE)
        
        if not result:
            return Response({'error': 'Usuario no encontrado'}, status=status.HTTP_404_NOT_FOUND)
            
        user_data = result[0][1]
        user = {
            'username': user_data['uid'][0].decode('utf-8'),
            'name': user_data['cn'][0].decode('utf-8'),
            'email': user_data.get('mail', [b''])[0].decode('utf-8'),
            'mail_quota': user_data.get('mailQuota', [b'0'])[0].decode('utf-8')
        }
        
        return Response(user)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def user_update(request, username):
    try:
        data = request.data
        conn = get_ldap_connection()
        user_dn = f'uid={username},{settings.LDAP_BASE_DN}'
        
        # Obtener datos actuales
        conn.search(settings.LDAP_BASE_DN, f'(uid={username})', SUBTREE)
        if not old_data:
            return Response({'error': 'Usuario no encontrado'}, status=status.HTTP_404_NOT_FOUND)
            
        old_attrs = old_data[0][1]
        new_attrs = {}
        
        if 'name' in data:
            new_attrs['cn'] = [data['name'].encode('utf-8')]
        if 'email' in data:
            new_attrs['mail'] = [data['email'].encode('utf-8')]
        if 'password' in data:
            new_attrs['userPassword'] = [data['password'].encode('utf-8')]
        if 'mail_quota' in data:
            # Validar que la cuota no exceda el límite establecido
            try:
                quota = int(data['mail_quota'])
                if quota > settings.MAX_MAIL_QUOTA:
                    return Response(
                        {'error': f'La cuota de correo no puede exceder {settings.MAX_MAIL_QUOTA} MB'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                new_attrs['mailQuota'] = [str(quota).encode('utf-8')]
            except ValueError:
                return Response(
                    {'error': 'La cuota de correo debe ser un número válido'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
        # Crear lista de modificaciones
        conn.modify(user_dn, {attr: [(MODIFY_REPLACE, [value])] for attr, value in new_attrs.items()})
        
        return Response({'message': 'Usuario actualizado exitosamente'})
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def user_delete(request, username):
    try:
        conn = get_ldap_connection()
        user_dn = f'uid={username},{settings.LDAP_BASE_DN}'
        
        conn.delete(user_dn)
        return Response({'message': 'Usuario eliminado exitosamente'})
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Funciones para gestión de grupos
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def group_list(request):
    try:
        conn = get_ldap_connection()
        search_filter = '(objectClass=groupOfNames)'
        attrs = ['cn', 'member']
        
        conn.search(settings.LDAP_BASE_DN, search_filter, SUBTREE, attributes=attrs)
        groups = [{'name': entry['cn'].value,
                  'members': [str(member) for member in entry['member'].values] if 'member' in entry else []}
                 for entry in conn.entries]
        
        return Response(groups)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def group_create(request):
    try:
        data = request.data
        conn = get_ldap_connection()
        
        group_dn = f'cn={data["name"]},{settings.LDAP_BASE_DN}'
        attrs = {
            'objectClass': [b'groupOfNames', b'top'],
            'cn': [data['name'].encode('utf-8')],
            'member': [member.encode('utf-8') for member in data.get('members', [])]
        }
        
        conn.add_s(group_dn, ldap.modlist.addModlist(attrs))
        return Response({'message': 'Grupo creado exitosamente'})
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def group_detail(request, groupname):
    try:
        conn = get_ldap_connection()
        search_filter = f'(cn={groupname})'
        conn.search(settings.LDAP_BASE_DN, search_filter, SUBTREE)
        
        if not result:
            return Response({'error': 'Grupo no encontrado'}, status=status.HTTP_404_NOT_FOUND)
            
        group_data = result[0][1]
        group = {
            'name': group_data['cn'][0].decode('utf-8'),
            'members': [member.decode('utf-8') for member in group_data.get('member', [])]
        }
        
        return Response(group)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def group_update(request, groupname):
    try:
        data = request.data
        if not data:
            return Response(
                {'error': 'No se proporcionaron datos para actualizar'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validar formato del nombre del grupo
        if not groupname.isalnum():
            return Response(
                {'error': 'El nombre del grupo solo puede contener letras y números'},
                status=status.HTTP_400_BAD_REQUEST
            )

        conn = get_ldap_connection()
        group_dn = f'cn={groupname},{settings.LDAP_BASE_DN}'
        
        # Verificar si el grupo existe
        conn.search(settings.LDAP_BASE_DN, f'(cn={groupname})', SUBTREE)
        if not conn.entries:
            return Response(
                {'error': 'Grupo no encontrado'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Validar miembros del grupo
        if 'members' in data:
            if not isinstance(data['members'], list):
                return Response(
                    {'error': 'El campo members debe ser una lista'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validar que los usuarios existan
            invalid_members = []
            for member in data['members']:
                if not isinstance(member, str):
                    return Response(
                        {'error': 'Los miembros del grupo deben ser cadenas de texto'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                member_filter = f'(uid={member})'
                conn.search(settings.LDAP_BASE_DN, member_filter, SUBTREE)
                if not conn.entries:
                    invalid_members.append(member)

            if invalid_members:
                return Response(
                    {'error': f'Los siguientes usuarios no existen: {", ".join(invalid_members)}'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Actualizar miembros
            new_members = [f'uid={member},{settings.LDAP_BASE_DN}'.encode('utf-8') 
                         for member in data['members']]
            conn.modify(group_dn, {'member': [(MODIFY_REPLACE, new_members)]})

        return Response({'message': 'Grupo actualizado exitosamente'})
    except Exception as e:
        error_msg = 'Error al actualizar el grupo'
        if 'no such object' in str(e).lower():
            error_msg = 'El grupo no existe'
        elif 'connection error' in str(e).lower():
            error_msg = 'Error de conexión con el servidor LDAP'
        return Response({'error': error_msg}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def group_delete(request, groupname):
    try:
        conn = get_ldap_connection()
        group_dn = f'cn={groupname},{settings.LDAP_BASE_DN}'
        
        conn.delete_s(group_dn)
        return Response({'message': 'Grupo eliminado exitosamente'})
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def move_user(request, username):
    try:
        data = request.data
        if 'old_dn' not in data or 'new_dn' not in data:
            return Response(
                {'error': 'Se requieren old_dn y new_dn'},
                status=status.HTTP_400_BAD_REQUEST
            )

        conn = get_ldap_connection()
        try:
            conn.modify_dn(data['old_dn'], data['new_dn'])
            return Response({'message': 'Usuario movido exitosamente'})
        except Exception as e:
            return Response(
                {'error': f'Error al mover usuario: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def search_ou(request):
    try:
        data = request.data
        if 'ou' not in data:
            return Response(
                {'error': 'Se requiere el parámetro ou'},
                status=status.HTTP_400_BAD_REQUEST
            )

        conn = get_ldap_connection()
        search_ou = f"{data['ou']},{settings.LDAP_BASE_DN}"
        
        conn.search(
            search_ou,
            '(objectClass=*)',
            SUBTREE,
            attributes=['ou', 'description']
        )

        ous = [{
            'ou': entry.ou.value if hasattr(entry, 'ou') else '',
            'description': entry.description.value if hasattr(entry, 'description') else ''
        } for entry in conn.entries]

        return Response(ous)
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
