# Generated by Django 4.1.13 on 2024-03-22 01:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userAuth', '0013_remove_temoinage_user_id'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='contact',
            name='id_user',
        ),
        migrations.AddField(
            model_name='contact',
            name='name',
            field=models.TextField(default=''),
        ),
    ]
