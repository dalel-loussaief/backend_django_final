# Generated by Django 4.1.13 on 2024-03-23 00:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Property', '0014_remove_property_image'),
    ]

    operations = [
        migrations.AddField(
            model_name='property',
            name='image',
            field=models.ImageField(default='default_image.jpg', upload_to='property_images/'),
        ),
    ]