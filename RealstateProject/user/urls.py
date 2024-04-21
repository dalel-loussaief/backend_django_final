from django.urls import path
from . import views
from django.contrib import admin
from django.urls import path , include
from .views import RegisterView
urlpatterns = [
    #path('',views.index),
    #path('add/',views.add_user),
    #path('show/',views.get_all_user),
    #path('admin/', admin.site.urls),
    # path('user/',include('user.urls')),
    path('register/', RegisterView.as_view())
]