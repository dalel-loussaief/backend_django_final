from django.db import models

# Create your models here.


class Blog(models.Model):
    title = models.CharField(max_length=255)
    date = models.DateField()
    description = models.TextField()
    image = models.ImageField(upload_to='blog_images/', default='default_image.jpg')  # stocker les images dans le répertoire 'media/blog_images/'

    def __str__(self):
        return self.title
