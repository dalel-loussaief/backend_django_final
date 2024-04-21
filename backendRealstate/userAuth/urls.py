from django.contrib import admin
from django.urls import path , include
from django.urls import path
from .views import envoyer_email, get_properties_by_email, PropertyInfoDeleteAPIView, \
    get_property_detail, update_property, PropertyDetailView
from . import views
from .views import RegisterView, LoginView, UserView, LogoutView, UserListByRoleId2APIView,UserListByRoleId3APIView,change_password,get_user_role
from django.conf import settings
from django.conf.urls.static import static
from .views import list_properties

urlpatterns = [
    path('users/', views.list_users, name='list-users'),
    path('role-create/', views.create_role, name='role-create'),
    path('role-update/<int:pk>/', views.update_role, name='role-update'),
    path('role-delete/<int:pk>/', views.delete_role, name='role-delete'),

    path('user-create/', views.create_user, name='user-create'),
    path('user-update/<int:pk>/', views.updateUser, name='user-update'),
    path('user-delete/<int:pk>/', views.deleteUser, name='user-delete'),
    path('user-search/<int:pk>/', views.searchUserById, name='user-search-by-id'),
    path('users/role2/', UserListByRoleId2APIView.as_view(), name='user-list-by-role2'),
    path('users/role3/', UserListByRoleId3APIView.as_view(), name='user-list-by-role3'),

    path('api/register', RegisterView.as_view()),
    path('api/login', LoginView.as_view()),
    path('api/user', UserView.as_view()),
    path('api/logout', LogoutView.as_view()),

    path('temoinage-create/', views.create_temoinage, name='temoinage-create'),
    path('temoinage-update/<int:pk>/', views.update_temoinage, name='temoinage-update'),
    path('temoinage-delete/<int:pk>/', views.delete_temoinage, name='temoinage-delete'),
    path('temoinages/', views.list_temoinages, name='list-temoinages'),
    path('temoinage-search/<int:pk>/', views.searchTemoinageById, name='temoinage-search-by-id'),

    path('blog-create/', views.create_blog, name='blog-create'),
    path('blog-update/<int:pk>/', views.update_blog, name='blog-update'),
    path('blog-delete/<int:pk>/', views.delete_blog, name='blog-delete'),
    path('blogs/', views.list_blogs, name='list-blogs'),
    path('blog-search/<int:pk>/', views.searchBlogById, name='blog-search-by-id'),
    path('blog-detail/<int:pk>/', views.ViewBlog, name='blog-detail'),

    path('api/add_contact/', views.add_contact, name='add_contact'),
    path('contact-update/<int:pk>/', views.update_contact, name='contact-update'),
    path('contact-delete/<int:pk>/', views.delete_contact, name='contact-delete'),
    path('contacts/', views.list_contacts, name='list-contacts'),
    path('contact-search/<int:pk>/', views.searchContactById, name='contact-search-by-id'),
    path('change_password/', change_password, name='change_password'),
   # path('api/get-role/<str:email>/', get_role_by_email, name='get_role_by_email'),

    path('user-role/<str:email>/', get_user_role, name='get_user_role'),
    path('rdv-create/', views.create_rdv, name='rdv-create'),
    path('rdv-delete/<int:pk>/', views.delete_rdv, name='rdv-delete'),
    path('rdvs/', views.list_rdvs, name='list-rdvs'),
    path('envoyer-email/', envoyer_email, name='envoyer_email'),

    path('property-list/', views.ShowAll, name='property-list'),
    path('property-detail/<int:id>/', views.ViewProperty, name='property-detail'),
    path('property-create/', views.CreateProperty, name='property-create'),
    path('property-update/<int:pk>/', views.updateProperty, name='property-update'),
   # path('property-delete/<int:pk>/', views.deleteProperty, name='property-delete'),
    path('property-search/<int:pk>/', views.searchPropertyById, name='property-search-by-id'),
    path('properties/', list_properties, name='list_properties'),
    path('propertyinfo-create/', views.create_propertyinfo, name='property-create'),
    path('properties/<str:email>/', get_properties_by_email, name='get_properties_by_email'),

    path('property/delete/<int:pk>/', PropertyInfoDeleteAPIView.as_view(), name='property-delete'),

    path('property/detail/<int:id>/', get_property_detail, name='property_detail'),
    path('property/update/<int:id>/', update_property, name='update_property'),

   # path('properties/<int:id>/', PropertyDetailView.as_view(), name='property-detail'),



    path('Show/', views.Show, name='show_category'),
    path('category-detail/<int:pk>', views.ViewCategory, name='category_detail'),
    path('category-create/', views.CreateCategory, name='category-create'),
    path('category-update/<int:pk>/', views.updateCategory, name='category-update'),
    path('category-delete/<int:pk>/', views.deleteCategory, name='category-delete'),
    path('category-search/<int:pk>/', views.searchCategoryById, name='category-search-by-id'),
    path('properties-by-category-and-service/<int:category_id>/<int:id_service>/',
         views.properties_by_category_and_service, name='properties-by-category-and-service'),

    path('service-list/', views.ShowAll, name='service-list'),
    path('service-detail/<int:pk>/', views.ViewService, name='service-detail'),
    path('service-create/', views.CreateService, name='service-create'),
    path('service-update/<int:pk>/', views.updateService, name='service-update'),
    path('service-delete/<int:pk>/', views.deleteService, name='service-delete'),
    path('service-search/<int:pk>/', views.searchServiceById, name='service-search-by-id'),
    path('createImage/', views.createImage, name='create_image'),
    path('updateImage/<int:pk>/', views.updateImage, name='image-update'),
    path('deleteImage/<int:pk>/', views.deleteImage),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)