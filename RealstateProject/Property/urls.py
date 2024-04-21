from django.urls import path
from . import views
from django.contrib import admin
from django.urls import path , include

urlpatterns = [
    #path('',views.index),
    path('add_property/', views.add_property),
    path('update_property/<int:id>', views.update_property),
    path('delete_property/<int:id>', views.delete_property),
    path('read_property/<int:id>', views.read_property),
    path('read_property_all/<int:id>', views.read_property_all),

]