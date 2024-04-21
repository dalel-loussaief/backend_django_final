from django.db import models



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