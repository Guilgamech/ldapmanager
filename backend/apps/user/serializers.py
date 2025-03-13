from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import User

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)
    ldap_dn = serializers.CharField(read_only=True)
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'password', 'email_quota', 'department', 'employee_number',
            'identification', 'service_internet', 'service_mail',
            'is_ldap_user', 'last_ldap_sync', 'is_active', 'date_joined',
            'ldap_dn'
        ]
        read_only_fields = ['last_ldap_sync', 'date_joined', 'ldap_dn']

    def validate_password(self, value):
        if value:
            validate_password(value)
        return value

    def validate_email_quota(self, value):
        if value and value <= 0:
            raise serializers.ValidationError('Email quota must be greater than 0')
        return value

    def validate_identification(self, value):
        if value and not value.isdigit():
            raise serializers.ValidationError('Identification must contain only digits')
        return value

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = User.objects.create(**validated_data)
        if password:
            user.set_password(password)
            user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance