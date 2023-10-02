from django.urls import path
from . import views

app_name = 'jwks' # check that app_name matches 'jwks'
urlpatterns = [
    path('jwks/', views.jwks_view, name='jwks'),
    path('auth/', views.auth_view, name='auth_view'),
]
