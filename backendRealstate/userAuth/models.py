from django.contrib.auth.base_user import BaseUserManager
from django.db import models
from django.contrib.auth.hashers import make_password




class Role(models.Model):

    name = models.CharField(max_length=50)

class User(models.Model):
    name = models.CharField(max_length=50)
    email = models.CharField(max_length=50, unique=True)
    password = models.CharField(max_length=255)
    phone = models.CharField(max_length=20)
    username = None
    role_id = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True)

    def set_password(self, password):
        self.password = make_password(password)


USERNAME_FIELD = 'email'
REQUIRED_FIELDS = []


class Temoinage(models.Model):
    name = models.TextField(default='')
    contenu = models.TextField()
    note = models.IntegerField()


class Blog(models.Model):
    titre = models.CharField(max_length=100)
    contenu = models.TextField()
    date = models.DateTimeField(auto_now_add=True)
    image = models.ImageField(upload_to='blog_images/', default='default_image.jpg')


    def __str__(self):
        return self.titre


class Contact(models.Model):
    name = models.TextField(default='')
    message = models.CharField(max_length=100, default='')
    email = models.EmailField(max_length=100, default='')

    def __str__(self):
        return self.description


class RDV(models.Model):
    fullname = models.CharField(max_length=100)
    email = models.EmailField()
    phone = models.CharField(max_length=20)
    date = models.DateField()
    property_title = models.CharField(max_length=255, default='')

    def _str_(self):
        return self.fullname


class Category(models.Model):
    category_id = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length=255)
class Service(models.Model):
    id_service = models.BigAutoField(primary_key=True)
    type_service = models.CharField(max_length=255)

class Property(models.Model):
    property_titre = models.CharField(max_length=255)
    property_description = models.TextField()
    property_surface = models.IntegerField()
    property_dispo = models.CharField(max_length=255)
    property_prix = models.IntegerField()
    image = models.ImageField(upload_to='property_images/', default='default_image.jpg')
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE, default=1)  # Ajout de default=None

    def __str__(self):
        return self.property_titre

class Image(models.Model):
    idImage = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=255)
    image = models.ImageField(upload_to='images/')  # Utilisez ImageField pour les images
    property = models.ForeignKey(Property, related_name='images', on_delete=models.CASCADE)
class PropertyInfo(models.Model):
    property_titre = models.CharField(max_length=255)
    property_description = models.TextField()
    property_surface = models.IntegerField()
    property_dispo = models.CharField(max_length=255)
    property_prix = models.IntegerField()
    image = models.ImageField(upload_to='property_images/', default='default_image.jpg')
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE, default=1)
    owner_email = models.EmailField()  # Champ pour stocker l'email du propriétaire

    def _str_(self):
        return self.property_titre
