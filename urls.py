from django.urls import path
from django.contrib.auth.views import LogoutView
from . import views

urlpatterns = [
    path('',views.indexpage, name = ""),
    path('signup',views.signup, name = "signup"),
    path('login',views.login, name = "login"),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('scan',views.scan, name = "scan"),
    path('scanExternal',views.scanExternal, name = "scanExternal"),
    path('education',views.education, name = "education"),
    path('networking-basics', views.networking_basics, name='networking-basics'),
    path('network-scanning', views.network_scanning, name='network-scanning'),
    path('cybersecurity-fundamentals', views.cybersecurity_fundamentals, name='cybersecurity-fundamentals'),
    path('hands-on-learning', views.hands_on_learning, name='hands-on-learning'),
    path('glossary-of-terms', views.glossary_of_terms, name='glossary-of-terms'),
    path('networking-tools', views.networking_tools, name='networking-tools'),
    path('features', views.features, name='features'),
    path('dashboard', views.dashboard, name='dashboard'),
]
