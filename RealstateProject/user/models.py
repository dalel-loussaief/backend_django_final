from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from .db_connection import db
# Create your models here.

user_collection = db['user']
class Role(models.Model):
    id_role = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)

class User(models.Model):
    groups = models.ManyToManyField(Group, related_name='custom_user_groups')
    user_permissions = models.ManyToManyField(Permission, related_name='custom_user_permissions')

    name = models.CharField(max_length=255)
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    username = None

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
