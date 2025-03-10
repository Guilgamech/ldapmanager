"""Django settings for ldapmanager project."""

from pathlib import Path
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv('DJANGO_DEBUG', 'False').lower() == 'true'

ALLOWED_HOSTS = os.getenv('DJANGO_ALLOWED_HOSTS', '').split(',')

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'drf_yasg',
    'corsheaders',
    'ldap_auth',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'ldapmanager.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'ldapmanager.wsgi.application'

# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'es-es'

TIME_ZONE = 'America/Santiago'

USE_I18N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Configuración CORS
CORS_ALLOWED_ORIGINS = os.getenv('CORS_ALLOWED_ORIGINS', '').split(',')

# Configuración LDAP
# LDAP Settings
LDAP_SERVER_URI = os.getenv('LDAP_SERVER_URI', 'ldap://localhost:389')
LDAP_BIND_DN = os.getenv('LDAP_BIND_DN', '')
LDAP_BIND_PASSWORD = os.getenv('LDAP_BIND_PASSWORD', '')
LDAP_BASE_DN = os.getenv('LDAP_BASE_DN', '')
LDAP_USER_SEARCH_BASE = os.getenv('LDAP_USER_SEARCH_BASE', '')
LDAP_GROUP_SEARCH_BASE = os.getenv('LDAP_GROUP_SEARCH_BASE', '')

# LDAP User Settings
LDAP_USER_OBJECT_CLASSES = ['top', 'person', 'organizationalPerson', 'user']
LDAP_USER_ATTRS = ['uid', 'cn', 'sn', 'mail', 'userAccountControl']
LDAP_DEFAULT_USER_ACCOUNT_CONTROL = 66048  # Normal account + Password never expires
LDAP_USER_SERVICES = {
    'serviceInternet': 'enable',
    'serviceMail': 'enable',
    'serviceJabber': 'enable',
    'serviceMailRecipient': 'int',
    'serviceMailSender': 'int'
}

# LDAP Configuration
LDAP_SERVER_URI = os.getenv('LDAP_SERVER_URI')
LDAP_BIND_DN = os.getenv('LDAP_BIND_DN')
LDAP_BIND_PASSWORD = os.getenv('LDAP_BIND_PASSWORD')
LDAP_BASE_DN = os.getenv('LDAP_BASE_DN')

# Mail Quota Settings
DEFAULT_MAIL_QUOTA = int(os.getenv('DEFAULT_MAIL_QUOTA', 1024))
MAX_MAIL_QUOTA = int(os.getenv('MAX_MAIL_QUOTA', 5120))

# LDAP User Configuration
LDAP_USER_OBJECT_CLASSES = ['top', 'person', 'organizationalPerson', 'inetOrgPerson']
LDAP_USER_SERVICES = {
    'serviceJabber': 'TRUE',
    'serviceInternet': 'TRUE',
    'serviceMail': 'TRUE'
}
LDAP_DEFAULT_USER_ACCOUNT_CONTROL = 512  # Normal user account

# Custom User Model
AUTH_USER_MODEL = 'ldap_auth.LDAPUser'

# CORS Configuration
CORS_ALLOWED_ORIGINS = os.getenv('CORS_ALLOWED_ORIGINS', '').split(',')
CORS_ALLOW_CREDENTIALS = True

# Rest Framework Configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}

# CORS Settings
CORS_ALLOW_ALL_ORIGINS = DEBUG
CORS_ALLOWED_ORIGINS = os.getenv('CORS_ALLOWED_ORIGINS', '').split(',')
CORS_ALLOW_CREDENTIALS = True