from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode

from .models import Role, User, Temoinage, Blog, Contact, RDV, Category, Service, Image, Property, PropertyInfo
from rest_framework import serializers, validators
from djoser.serializers import UserSerializer
from django.contrib.auth import get_user_model



class TemoinageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Temoinage
        fields = '__all__'


class BlogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blog
        fields = '__all__'


class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = '__all__'



class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = '__all__'


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'password','phone','role_id']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance



from rest_framework import serializers

class RdvSerializer(serializers.ModelSerializer):
    class Meta:
        model = RDV
        fields = '__all__'  # or specify a list of fields ['field1', 'field2', ...]
class PropertySerializer(serializers.ModelSerializer):

    class Meta:
        model = Property
        fields = '__all__'

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'

class ServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = '__all__'

class ImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Image
        fields = ['idImage', 'name', 'type', 'image', 'property_id']

class PropertyinfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = PropertyInfo
        fields = '__all__'  # or specify a list of fields if you don't want to include all fields
class PropertyInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = PropertyInfo
        fields = ['property_titre', 'property_description', 'property_surface', 'property_dispo', 'property_prix','image','category','service']



