from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE
from django.conf import settings
from datetime import datetime
from typing import Optional, Dict, Any, List

class LDAPManager:
    def __init__(self):
        self.server = Server('ldaps://reduc.edu.cu:636', get_info=ALL, use_ssl=True)
        self.base_dn = 'OU=CATALOGO,DC=reduc,DC=edu,DC=cu'
        self.search_dn = 'DC=reduc,DC=edu,DC=cu'
        self.connection = None

    def connect(self, username: str, password: str) -> bool:
        """Establish LDAP connection with credentials"""
        try:
            self.connection = Connection(
                self.server,
                user=username,
                password=password,
                authentication='SIMPLE'
            )
            return self.connection.bind()
        except Exception as e:
            raise Exception(f'LDAP connection failed: {str(e)}')

    def disconnect(self) -> None:
        """Close LDAP connection"""
        if self.connection:
            self.connection.unbind()
            self.connection = None

    def search_user(self, query: str) -> List[Dict[str, Any]]:
        """Search for users in LDAP"""
        if not self.connection:
            raise Exception('No LDAP connection established')

        mail_format = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        ci_format = r'^\d{11}$'

        if query.match(mail_format):
            search_filter = f'(mail={query})'
        elif query.match(ci_format):
            search_filter = f'(identification={query})'
        else:
            search_filter = f'(|(cn=*{query}*)(sn=*{query}*))'

        attributes = [
            'dn', 'displayName', 'givenName', 'sAMAccountName',
            'identification', 'description', 'mail', 'whenCreated',
            'whenChanged', 'role', 'serviceJabber', 'serviceInternet',
            'serviceMail', 'userAccountControl', 'mailQuota'
        ]

        self.connection.search(
            search_base=self.search_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes
        )

        return [entry['attributes'] for entry in self.connection.entries]

    def add_user(self, dn: str, attributes: Dict[str, Any]) -> bool:
        """Add a new user to LDAP"""
        if not self.connection:
            raise Exception('No LDAP connection established')

        attributes.update({
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'userAccountControl': 66048,
            'serviceInternet': 'enable',
            'serviceMail': 'enable',
            'serviceJabber': 'enable',
            'serviceMailRecipient': 'int',
            'serviceMailSender': 'int'
        })

        if 'unicodePwd' in attributes:
            attributes['unicodePwd'] = f'"{attributes["unicodePwd"]}"'.encode('utf-16-le')

        return self.connection.add(dn, attributes=attributes)

    def modify_user(self, dn: str, modifications: Dict[str, Any]) -> bool:
        """Modify existing user in LDAP"""
        if not self.connection:
            raise Exception('No LDAP connection established')

        changes = {}
        for attr, value in modifications.items():
            if attr == 'unicodePwd':
                value = f'"{value}"'.encode('utf-16-le')
            changes[attr] = [(MODIFY_REPLACE, [value])]

        return self.connection.modify(dn, changes)

    def delete_user(self, dn: str) -> bool:
        """Delete user from LDAP"""
        if not self.connection:
            raise Exception('No LDAP connection established')

        return self.connection.delete(dn)

    def move_user(self, old_dn: str, new_dn: str) -> bool:
        """Move user to a different OU in LDAP"""
        if not self.connection:
            raise Exception('No LDAP connection established')

        return self.connection.modify_dn(old_dn, new_dn)