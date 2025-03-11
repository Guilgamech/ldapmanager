from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from django.utils import timezone
from .ldap_utils import LDAPManager
from typing import Optional, Tuple, Any

User = get_user_model()

class LDAPAuthBackend(BaseBackend):
    """Custom authentication backend for LDAP users"""

    def authenticate(self, request: Any, username: str, password: str) -> Optional[User]:
        """Authenticate a user against LDAP and sync their details"""
        ldap = LDAPManager()

        try:
            # Attempt LDAP authentication
            if not ldap.connect(username, password):
                return None

            # Search for user details in LDAP
            users = ldap.search_user(username)
            if not users:
                return None

            ldap_user = users[0]
            
            # Get or create local user
            user, created = User.objects.get_or_create(
                username=ldap_user['sAMAccountName'],
                defaults={
                    'email': ldap_user['mail'],
                    'first_name': ldap_user.get('givenName', ''),
                    'last_name': ldap_user.get('sn', ''),
                    'is_ldap_user': True,
                    'ldap_dn': ldap_user['dn'],
                    'department': ldap_user.get('description', ''),
                    'email_quota': int(ldap_user.get('mailQuota', 1024))
                }
            )

            if not created:
                # Update existing user's details
                user.email = ldap_user['mail']
                user.first_name = ldap_user.get('givenName', '')
                user.last_name = ldap_user.get('sn', '')
                user.department = ldap_user.get('description', '')
                user.email_quota = int(ldap_user.get('mailQuota', 1024))
                user.last_ldap_sync = timezone.now()
                user.save()

            return user

        except Exception as e:
            print(f'LDAP authentication failed: {str(e)}')
            return None
        finally:
            ldap.disconnect()

    def get_user(self, user_id: int) -> Optional[User]:
        """Retrieve user by ID"""
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None