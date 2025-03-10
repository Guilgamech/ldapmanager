from functools import wraps
from django.http import JsonResponse
from django.conf import settings
from ldap3 import Server, Connection, ALL, SUBTREE
import re
import base64
from .models import LDAPUser

class LDAPMiddleware:
    def __init__(self):
        self.client = None

    def get_ldap_connection(self):
        """Create and return a new LDAP connection"""
        if not self.client:
            try:
                server = Server(settings.LDAP_SERVER_URI, get_info=ALL)
                self.client = Connection(
                    server,
                    settings.LDAP_BIND_DN,
                    settings.LDAP_BIND_PASSWORD,
                    auto_bind=True
                )
            except Exception as e:
                print(f'[LDAP CONNECTION ERROR]: {str(e)}')
                raise
        return self.client

    def authenticate_token(self, request):
        """Authenticate user using Bearer token"""
        auth_header = request.headers.get('Authorization')
        if not auth_header or 'Bearer ' not in auth_header:
            return None, 'Encabezado de autorización faltante o inválido'

        try:
            token = auth_header.split(' ')[1]
            credentials = base64.b64decode(token).decode('utf-8')
            username, password = credentials.split(':')

            # Validate username format
            if not username.isalnum() or len(username) < 3 or len(username) > 50:
                return None, 'Formato de nombre de usuario inválido'

            # Validate credentials against LDAP
            conn = self.get_ldap_connection()
            user_dn = f'uid={username},{settings.LDAP_BASE_DN}'
            
            try:
                if conn.rebind(user=user_dn, password=password):
                    return username, None
                return None, 'Credenciales inválidas'
            except Exception as e:
                if 'invalid credentials' in str(e).lower():
                    return None, 'Credenciales inválidas'
                return None, 'Error de autenticación'

        except Exception as e:
            return None, str(e)

    def search_users(self, query):
        """Search users in LDAP directory"""
        conn = self.get_ldap_connection()
        
        # Define regex patterns for different search types
        email_pattern = re.compile(r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$')
        id_pattern = re.compile(r'^\d{11}$')
        
        # Determine search filter based on query type
        if email_pattern.match(query):
            search_filter = f'(mail={query})'
        elif id_pattern.match(query):
            search_filter = f'(identification={query})'
        else:
            search_filter = f'(|(cn=*{query}*)(sn=*{query}*))'
        
        # Define search attributes
        attributes = [
            'dn', 'displayName', 'givenName', 'sAMAccountName',
            'identification', 'description', 'mail', 'whenCreated',
            'whenChanged', 'role', 'serviceJabber', 'serviceInternet',
            'serviceMail', 'userAccountControl', 'mailQuota'
        ]
        
        try:
            conn.search(
                settings.LDAP_BASE_DN,
                search_filter,
                SUBTREE,
                attributes=attributes,
                time_limit=60
            )
            
            users = [entry for entry in conn.entries]
            return users, None
            
        except Exception as e:
            return None, str(e)

    def cleanup(self):
        """Clean up LDAP connection"""
        if self.client:
            try:
                self.client.unbind()
            except:
                pass
            finally:
                self.client = None

def ldap_auth_required(view_func):
    """Decorator for views that require LDAP authentication"""
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        middleware = LDAPMiddleware()
        
        try:
            username, error = middleware.authenticate_token(request)
            if error:
                return JsonResponse({'error': error}, status=401)
                
            # Attach authenticated user to request
            request.ldap_user = username
            return view_func(request, *args, **kwargs)
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
        finally:
            middleware.cleanup()
            
    return wrapped_view