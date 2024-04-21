
from django.urls import path , include
from . import views

from django.conf import settings
from django.conf.urls.static import static
from django.urls import path

from .views import list_properties

urlpatterns = [
    # path('', views.apiOverview, name='apiOverview'),
    path('property-list/', views.ShowAll, name='property-list'),
    path('property-detail/<int:pk>/', views.ViewProperty, name='property-detail'),
    path('property-create/', views.CreateProperty, name='property-create'),
    path('property-update/<int:pk>/', views.updateProperty, name='property-update'),
    path('property-delete/<int:pk>/', views.deleteProperty, name='property-delete'),
    path('property-search/<int:pk>/', views.searchPropertyById, name='property-search-by-id'),
    path('properties/', list_properties, name='list_properties'),


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