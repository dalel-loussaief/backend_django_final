# Generated by Django 4.1.13 on 2024-03-22 22:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Property', '0008_alter_image_image'),
    ]

    operations = [
        migrations.AddField(
            model_name='property',
            name='image',
            field=models.ImageField(default='default_image.jpg', upload_to='property_images/'),
        ),
    ]
