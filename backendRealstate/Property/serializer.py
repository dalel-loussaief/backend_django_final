from rest_framework import serializers
from .models import Category, Service
from .models import Property
from .models import Image
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