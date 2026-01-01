from django.urls import path
from . import views

urlpatterns = [
    # Páginas principales
    path('', views.index, name='frontend_index'),
    path('results/', views.results, name='frontend_results'),
    path('predict/', views.predict, name='frontend_predict'),
    path('api-docs/', views.api_docs, name='api_docs'),
    path('download-template/<str:template_type>/', views.download_template, name='download_template'),
    
    # Endpoints API internos
    path('api/process-dataset/', views.api_process_dataset, name='api_process_dataset'),
    path('api/predict/', views.api_predict, name='api_predict'),
    path('api/batch-predict/', views.api_batch_predict, name='api_batch_predict'),
    path('api/process-file/', views.api_process_file, name='api_process_file'),
    path('api/model-metrics/', views.api_model_metrics, name='api_model_metrics'),
]