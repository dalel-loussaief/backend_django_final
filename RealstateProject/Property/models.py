from django.db import models

from .db_connection import db
# Create your models here.

Property_collection = db['Property']
# Create your models here.

class Property(models.Model):
    _id = models.ObjectIdField()
    property_titre = models.CharField(max_length=255)
    property_description = models.TextField()
    property_surface = models.IntegerField()
    property_dispo = models.CharField(max_length=255)
    property_prix = models.IntegerField()
   # property_photo = models.ImageField(upload_to='property_photos/')
