from django.shortcuts import render

from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from .serializer import PropertySerializer, ServiceSerializer
from .serializer import CategorySerializer,ImageSerializer
from .models import Property, Service
from .models import Category
from .models import Property, Image
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
import base64
from rest_framework.decorators import parser_classes
from rest_framework.parsers import MultiPartParser
from rest_framework.parsers import MultiPartParser, FormParser


# Create your views here.

"""@api_view(['GET'])
def apiOverview(request):
    api_urls = {
        'List': '/property-list/',
        'Detail View': '/property-detail/<int:id>/',
        'Create': '/property-create/',
        'Update': '/property-update/<int:id>/',
        'Delete': '/property-detail/<int:id>/',
    }
    return Response(api_urls);
"""

@api_view(['GET'])
def ShowAll(request):
    property = Property.objects.all()
    serializer = PropertySerializer(property, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def  ViewProperty(request, pk):
    property = Property.objects.get(id=pk)
    serializer = PropertySerializer(property, many=False)
    return Response(serializer.data)

@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
def CreateProperty(request):
    if request.method == 'POST':
        serializer = PropertySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def updateProperty(request, pk):
    try:
        property_instance = Property.objects.get(id=pk)
    except Property.DoesNotExist:
        return Response({"error": "Property not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = PropertySerializer(instance=property_instance, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
def deleteProperty(request, pk):
    try:
        property_instance = Property.objects.get(id=pk)
    except Property.DoesNotExist:
        return Response({"error": "Property not found"}, status=status.HTTP_404_NOT_FOUND)

    property_instance.delete()
    return Response('Item deleted successfully!', status=status.HTTP_200_OK)

@api_view(['GET'])
def searchPropertyById(request, pk):
    try:
        property_instance = Property.objects.get(id=pk)
        serializer = PropertySerializer(property_instance)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Property.DoesNotExist:
        return Response({"error": "Property not found"}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def Show(request):
    category = Category.objects.all()
    serializer = CategorySerializer(category, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def ViewCategory(request, pk):
    category = Category.objects.get(category_id=pk)
    serializer = CategorySerializer(category, many=False)
    return Response(serializer.data)


@api_view(['POST'])
def CreateCategory(request):
    if request.method == 'POST':
        serializer = CategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def updateCategory(request, pk):
    try:
        category_instance = Category.objects.get(category_id=pk)
    except Category.DoesNotExist:
        return Response({"error": "category not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = CategorySerializer(instance=category_instance, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(['DELETE'])
def deleteCategory(request, pk):
    try:
        category_instance = Category.objects.get(category_id=pk)
    except Category.DoesNotExist:
        return Response({"error": "category not found"}, status=status.HTTP_404_NOT_FOUND)

    category_instance.delete()
    return Response('Category deleted successfully!', status=status.HTTP_200_OK)


@api_view(['GET'])
def searchCategoryById(request, pk):
    try:
        category_instance = Category.objects.get(category_id=pk)
        serializer = CategorySerializer(category_instance)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Category.DoesNotExist:
        return Response({"error": "category not found"}, status=status.HTTP_404_NOT_FOUND)



@api_view(['GET'])
def properties_by_category_and_service(request, category_id, id_service):
    try:
        category_instance = Category.objects.get(category_id=category_id)
    except Category.DoesNotExist:
        return Response({"error": "Category not found"}, status=status.HTTP_404_NOT_FOUND)

    try:
        service_instance = Service.objects.get(id_service=id_service)
    except Service.DoesNotExist:
        return Response({"error": "Service not found"}, status=status.HTTP_404_NOT_FOUND)

    properties = Property.objects.filter(category=category_instance, service=service_instance)
    serializer = PropertySerializer(properties, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)



@api_view(['GET'])
def ShowAll(request):
    services = Service.objects.all()
    serializer = ServiceSerializer(services, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def ViewService(request, pk):
    try:
        service = Service.objects.get(id_service=pk)
    except Service.DoesNotExist:
        return Response({"message": "Service does not exist"}, status=status.HTTP_404_NOT_FOUND)

    serializer = ServiceSerializer(service)
    return Response(serializer.data)


@api_view(['POST'])
def CreateService(request):
    if request.method == 'POST':
        serializer = ServiceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def updateService(request, pk):
    try:
        service_instance = Service.objects.get(id_service=pk)
    except Service.DoesNotExist:
        return Response({"error": "Service not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = ServiceSerializer(instance=service_instance, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
def deleteService(request, pk):
    try:
        service_instance = Service.objects.get(id_service=pk)
    except Service.DoesNotExist:
        return Response({"error": "Service not found"}, status=status.HTTP_404_NOT_FOUND)

    service_instance.delete()
    return Response('Item deleted successfully!', status=status.HTTP_200_OK)


@api_view(['GET'])
def searchServiceById(request, pk):
    try:
        service_instance = Service.objects.get(id_service=pk)
        serializer = ServiceSerializer(service_instance)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Service.DoesNotExist:
        return Response({"error": "Service not found"}, status=status.HTTP_404_NOT_FOUND)









@api_view(['POST'])
@parser_classes([MultiPartParser])
def createImage(request):
    if request.method == 'POST':
        serializer = ImageSerializer(data=request.data)
        if serializer.is_valid():
            property_id = request.data.get('property_id')
            try:
                property_instance = Property.objects.get(id=property_id)
            except Property.DoesNotExist:
                return Response({"error": "Property not found"}, status=status.HTTP_404_NOT_FOUND)

            image_file = request.data.get('image')
            image_content_type = image_file.content_type

            # Vérifiez le type de contenu de l'image avant de la sauvegarder
            if image_content_type not in ['image/jpeg', 'image/png', 'image/gif']:
                return Response({"error": "Unsupported image format"}, status=status.HTTP_400_BAD_REQUEST)

            # Associer l'image à la propriété et la sauvegarder
            serializer.save(property=property_instance)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PUT'])
@parser_classes([MultiPartParser])
def updateImage(request, pk):
    try:
        image_instance = Image.objects.get(idImage=pk)  # Utilisez le champ correct ici
    except Image.DoesNotExist:
        return Response({"error": "Image not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serializer = ImageSerializer(instance=image_instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
def deleteImage(request, pk):
    try:
        image_instance = Image.objects.get(idImage=pk)  # Utilisez le champ d'identification correct ici
    except Image.DoesNotExist:
        return Response({"error": "Image not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        image_instance.delete()
        return Response({"message": "Image deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
def list_properties(request):
    properties = Property.objects.all()
    serializer = PropertySerializer(properties, many=True)
    return Response(serializer.data)