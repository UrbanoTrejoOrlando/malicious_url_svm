from django.urls import path
from .views import (
    ProcessDatasetView, 
    PredictURLView, 
    BatchPredictView, 
    ProcessFileView, 
    ModelMetricsView,
    ResultsView
)

urlpatterns = [
    path('process-dataset/', ProcessDatasetView.as_view(), name='process_dataset'),
    path('predict-url/', PredictURLView.as_view(), name='predict_url'),
    path('predict-batch/', BatchPredictView.as_view(), name='predict_batch'),
    path('process-file/', ProcessFileView.as_view(), name='process_file'),
    path('model-metrics/', ModelMetricsView.as_view(), name='model_metrics'),
    path('results/', ResultsView.as_view(), name='results-view'),  # <-- Añade esta línea
]