import json

import django
from django.shortcuts import render
from pymongo import MongoClient
from django.http import JsonResponse
from django.http import HttpResponse
from .models import Property_collection, Property
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
# Create your views here.
client = MongoClient('localhost’, 27017')
db = client['RealestateDataBase']

@csrf_exempt
def add_property(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            property_titre = data.get("property_titre")
            property_description = data.get("property_description")
            property_surface = data.get("property_surface")
            property_dispo = data.get("property_dispo")
            property_prix = data.get("property_prix")

            # Vérifiez si toutes les données nécessaires sont présentes
            if property_titre and property_description and property_surface and property_dispo and property_prix:
                # Créer et sauvegarder l'objet Property
                pro = Property(
                    property_titre=property_titre,
                    property_description=property_description,
                    property_surface=property_surface,
                    property_dispo=property_dispo,
                    property_prix=property_prix
                )
                pro.save()
                return JsonResponse({'message': 'Property inserted successfully'}, status=201)
            else:
                return JsonResponse({'error': 'Missing required fields'}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)


def update_property(request ,id):
    pass
def delete_property (request ,id):
    pass
def read_property(resquest ,id):
    pass

def read_property_all(request ,id):
    pass