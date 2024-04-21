
from django.shortcuts import render
from .models import user_collection
from django.http import HttpResponse
from pymongo import MongoClient
from rest_framework.views import APIView
from .Serializer  import UserSerializer
from rest_framework.response import Response

# Create your views here.




client = MongoClient('localhost’, 27017')
db = client['RealestateDataBase']
class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


