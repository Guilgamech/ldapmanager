from django.urls import path
from . import views

app_name = 'ldap_auth'

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('users/', views.user_list, name='user_list'),
    path('users/create/', views.user_create, name='user_create'),
    path('users/<str:username>/', views.user_detail, name='user_detail'),
    path('users/<str:username>/update/', views.user_update, name='user_update'),
    path('users/<str:username>/delete/', views.user_delete, name='user_delete'),
    path('users/<str:username>/move/', views.move_user, name='move_user'),
    path('groups/', views.group_list, name='group_list'),
    path('groups/create/', views.group_create, name='group_create'),
    path('groups/<str:groupname>/', views.group_detail, name='group_detail'),
    path('groups/<str:groupname>/update/', views.group_update, name='group_update'),
    path('groups/<str:groupname>/delete/', views.group_delete, name='group_delete'),
    path('ou/search/', views.search_ou, name='search_ou'),
]