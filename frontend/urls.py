from django.urls import path
from .views import index, results, predict, download_template

urlpatterns = [
    path('', index, name='index'),
    path('results/', results, name='results'),
    path('predict/', predict, name='predict'),
    path('download-template/<str:template_type>/', download_template, name='download_template'),
]