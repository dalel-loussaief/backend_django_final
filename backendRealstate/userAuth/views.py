from rest_framework.decorators import api_view, parser_classes
from rest_framework.generics import RetrieveAPIView

from .serializer import RoleSerializer, TemoinageSerializer, BlogSerializer, ContactSerializer, RegisterSerializer, \
    RdvSerializer, PropertySerializer, ImageSerializer, ServiceSerializer, CategorySerializer, PropertyinfoSerializer
from .models import User, Temoinage, Blog, Contact, RDV, Image, Property, Service, Category, PropertyInfo
from .models import Role
from .models import Property
from .serializer import PropertyInfoSerializer
import jwt, datetime
from django.conf import settings
from rest_framework import status
from .models import PropertyInfo
from .serializer import PropertyinfoSerializer
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.hashers import check_password
from django.utils import timezone
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import parser_classes
from rest_framework import generics
from .models import User
from .serializer import UserSerializer
# Create your views here.

"""User"""
@api_view(['POST'])
def create_user(request):
    if request.method == 'POST':
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PUT'])
def updateUser(request, pk):
    try:
        user = User.objects.get(pk=pk)
    except User.DoesNotExist:
        return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serializer = UserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
def deleteUser(request, pk):
    try:
        user = User.objects.get(pk=pk)
    except User.DoesNotExist:
        return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        user.delete()
        return Response({"message": "User deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

@api_view(['GET'])
def searchUserById(request, pk):
    try:
        user = User.objects.get(pk=pk)
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
def list_users(request):
    users = User.objects.all()
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

"""Role"""
@api_view(['POST'])
def create_role(request):
    if request.method == 'POST':
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
@api_view(['PUT'])
def update_role(request, pk):
    try:
        role = Role.objects.get(pk=pk)
    except Role.DoesNotExist:
        return Response({"message": "Role not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serializer = RoleSerializer(role, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
def delete_role(request, pk):
    try:
        role = Role.objects.get(pk=pk)
    except Role.DoesNotExist:
        return Response({"message": "Role not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        role.delete()
        return Response({"message": "Role deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

"""Temoinage"""
@api_view(['POST'])
def create_temoinage(request):
        if request.method == 'POST':
            serializer = TemoinageSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PUT'])
def update_temoinage(request, pk):
    try:
        temoinage = Temoinage.objects.get(pk=pk)
    except Temoinage.DoesNotExist:
        return Response({"message": "Temoinage not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serializer = TemoinageSerializer(temoinage, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
@api_view(['DELETE'])
def delete_temoinage(request, pk):
    try:
        temoinage = Temoinage.objects.get(pk=pk)
    except Temoinage.DoesNotExist:
        return Response({"message": "Temoinage not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        temoinage.delete()
        return Response({"message": "Temoinage deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

@api_view(['GET'])
def list_temoinages(request):
    temoinages = Temoinage.objects.all()
    serializer = TemoinageSerializer(temoinages, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
def searchTemoinageById(request, pk):
    try:
        temoinage = Temoinage.objects.get(pk=pk)
        serializer = TemoinageSerializer(temoinage)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Temoinage.DoesNotExist:
        return Response({"message": "Temoinage not found"}, status=status.HTTP_404_NOT_FOUND)


"""Blog"""
@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
def create_blog(request):
        if request.method == 'POST':
            serializer = BlogSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PUT'])
def update_blog(request, pk):
    try:
        blog = Blog.objects.get(pk=pk)
    except Blog.DoesNotExist:
        return Response({"message": "Blog not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serializer = BlogSerializer(blog, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
def delete_blog(request, pk):
    try:
        blog = Blog.objects.get(pk=pk)
    except Blog.DoesNotExist:
        return Response({"message": "Blog not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        blog.delete()
        return Response({"message": "Blog deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
def list_blogs(request):
    blogs = Blog.objects.all()
    serializer = BlogSerializer(blogs, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
def searchBlogById(request, pk):
    try:
        blog = Blog.objects.get(pk=pk)
        serializer = BlogSerializer(blog)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Blog.DoesNotExist:
        return Response({"message": "Blog not found"}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def ViewBlog(request, pk):
    try:
        blog = Blog.objects.get(id=pk)
    except Blog.DoesNotExist:
        return Response({"message": "Blog does not exist"}, status=status.HTTP_404_NOT_FOUND)

    serializer = BlogSerializer(blog)
    return Response(serializer.data)


"""Contact"""
@api_view(['POST'])
def add_contact(request):
    if request.method == 'POST':
        serializer = ContactSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PUT'])
def update_contact(request, pk):
    try:
        contact = Contact.objects.get(pk=pk)
    except Contact.DoesNotExist:
        return Response({"message": "Contact not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serializer = ContactSerializer(contact, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
def delete_contact(request, pk):
    try:
        contact = Contact.objects.get(pk=pk)
    except Contact.DoesNotExist:
        return Response({"message": "Contact not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        contact.delete()
        return Response({"message": "Contact deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
def list_contacts(request):
    contacts = Contact.objects.all()
    serializer = ContactSerializer(contacts, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
def searchContactById(request, pk):
    try:
        contact = Contact.objects.get(pk=pk)
        serializer = ContactSerializer(contact)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Contact.DoesNotExist:
        return Response({"message": "Contact not found"}, status=status.HTTP_404_NOT_FOUND)





"""Register / Login"""
class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        user.set_password(request.data.get('password'))  # Set password before saving
        user.save()
        return Response(serializer.data)



class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        # Vérification de l'existence de l'utilisateur
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found!')

        # Vérification du mot de passe
        if not check_password(password, user.password):
            raise AuthenticationFailed('Incorrect password!')

        # Génération du token JWT
        token = generate_jwt_token(user)
        return Response({'token': token, 'role': user.role_id.name})

def generate_jwt_token(user):
    payload = {
        'user_id': user.id,
        'exp': timezone.now() + timezone.timedelta(minutes=60),
        'iat': timezone.now()
    }
    # Vous pouvez ajouter d'autres informations dans le payload si nécessaire
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')


class UserView(APIView):
    permission_classes = []

    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token!')

        user_id = payload.get('user_id')
        user = User.objects.filter(id=user_id).first()

        if not user:
            raise AuthenticationFailed('User not found!')

        serializer = RegisterSerializer(user)
        return Response(serializer.data)

class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'success'
        }
        return response


class UserListAPIView(generics.ListAPIView):
    serializer_class = UserSerializer

    def get_queryset(self):
        return User.objects.filter(role_id=3)


class UserListByRoleId2APIView(generics.ListAPIView):
    queryset = User.objects.filter(role_id=2)
    serializer_class = UserSerializer

class UserListByRoleId3APIView(generics.ListAPIView):
    queryset = User.objects.filter(role_id=3)
    serializer_class = UserSerializer

# Dans views.py

# Dans votre fichier views.py

from django.contrib.auth.hashers import make_password
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import User


@csrf_exempt
def change_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({'message': 'Utilisateur non trouvé'}, status=404)

        if not check_password(old_password, user.password):
            return JsonResponse({'message': 'Mot de passe incorrect'}, status=400)

        user.password = make_password(new_password)
        user.save()
        # Dans votre vue Django
        print(request.POST)

        return JsonResponse({'message': 'Mot de passe changé avec succès'}, status=200)
    else:
        return JsonResponse({'message': 'Méthode non autorisée'}, status=405)


from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import User

#@api_view(['GET'])
#def get_role_by_email(request, email):
    #try:
        #user = User.objects.get(email=email)
        #role_name = user.role_id.name if user.role_id else "No role assigned"
        #return Response({'role': role_name})
    #except User.DoesNotExist:
        #return Response({'error': 'User not found'}, status=404)

from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .models import User

from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .models import User  # Assurez-vous d'importer le modèle User

from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .models import User

@api_view(['GET'])
def get_user_role(request, email):
    user = get_object_or_404(User, email=email)
    role = user.role_id.name if user.role_id else None
    data = {'email': user.email, 'role': role}
    return Response(data)



@api_view(['POST'])
def create_rdv(request):
        if request.method == 'POST':
            serializer = RdvSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
def delete_rdv(request, pk):
    try:
        rdv = RDV.objects.get(pk=pk)
    except RDV.DoesNotExist:
        return Response({"message": "RDV not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        rdv.delete()
        return Response({"message": "RDV deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
def list_rdvs(request):
    rdvs = RDV.objects.all()
    serializer = RdvSerializer(rdvs, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


# Dans views.py

from django.core.mail import send_mail
from rest_framework.decorators import api_view
from rest_framework.response import Response

@api_view(['POST'])
def envoyer_email(request):
    if request.method == 'POST':
        data = request.data
        email_destinataire = data.get('email_destinataire')
        contenu_email = data.get('contenu_email')

        try:
            send_mail(
                'Objet de l\'email',
                contenu_email,
                'votre@email.com',  # L'adresse email de l'expéditeur
                [email_destinataire],
                fail_silently=False,
            )
            return Response({'message': 'Email envoyé avec succès !'})
        except Exception as e:
            return Response({'message': 'Erreur lors de l\'envoi de l\'e-mail : ' + str(e)}, status=500)


@api_view(['GET'])
def ShowAll(request):
    property = Property.objects.all()
    serializer = PropertyinfoSerializer(property, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def  ViewProperty(request, id):
    property = Property.objects.get(id=id)
    serializer = PropertyinfoSerializer(property, many=False)
    return Response(serializer.data)


from django.contrib.auth.decorators import login_required
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


from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import Category, Service, PropertyInfo
from .serializer import PropertyInfoSerializer

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import PropertyInfo, Category, Service
from .serializer import PropertyInfoSerializer

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

    properties = PropertyInfo.objects.filter(category=category_instance, service=service_instance)
    serializer = PropertyInfoSerializer(properties, many=True)
    properties_data = serializer.data

    # Ajouter l'ID de la propriété à chaque objet de propriété
    for i, property_data in enumerate(properties_data):
        property_data['id'] = properties[i].id

    return Response(properties_data, status=status.HTTP_200_OK)




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
    properties = PropertyInfo.objects.all()
    serializer = PropertyinfoSerializer(properties, many=True)
    return Response(serializer.data)



@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
def create_propertyinfo(request):
    if request.method == 'POST':
        serializer = PropertyinfoSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def get_properties_by_email(request, email):
    try:
        properties = PropertyInfo.objects.filter(owner_email=email)
        serializer = PropertyinfoSerializer(properties, many=True)
        return Response(serializer.data)
    except PropertyInfo.DoesNotExist:
        return Response({'message': 'No properties found for this email'}, status=404)
    except Exception as e:
        return Response({'error': str(e)},status=500)



class PropertyInfoDeleteAPIView(generics.DestroyAPIView):
    queryset = PropertyInfo.objects.all()
    serializer_class = PropertyinfoSerializer

    def delete(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            self.perform_destroy(instance)
            return Response(status=status.HTTP_204_NO_CONTENT)
        except:
            return Response(status=status.HTTP_404_NOT_FOUND)





from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import PropertyInfo
from .serializer import PropertyinfoSerializer

@api_view(['GET'])

def get_property_detail(request, id):
    try:
        property_info = PropertyInfo.objects.filter(id=id).first()
        if property_info:
            serializer = PropertyinfoSerializer(property_info)
            property_data = serializer.data
            property_data['id'] = property_info.id  # Ajoutez l'ID à l'objet de propriété
            return Response(property_data, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Property does not exist'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PropertyDetailView(RetrieveAPIView):
    queryset = Property.objects.all()
    serializer_class = PropertyinfoSerializer
    lookup_field = 'id'  # Utilisez 'id' comme champ de recherche

from rest_framework import status

@api_view(['PUT'])
def update_property(request, id):
    try:
        property_info = PropertyInfo.objects.get(id=id)
    except PropertyInfo.DoesNotExist:
        return Response({'message': 'Property does not exist'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serializer = PropertyInfoSerializer(property_info, data=request.data)
        if serializer.is_valid():
            serializer.save()
            updated_property_info = serializer.data
            updated_property_info['id'] = id  # Ajouter l'ID de la propriété à la réponse
            return Response(updated_property_info)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)









