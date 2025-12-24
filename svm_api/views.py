import json
import csv
import io
import re
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework import status
import pandas as pd
from .utils.model_processor import predict_single_url, batch_predict, process_dataset

class PredictURLView(APIView):
    def post(self, request):
        try:
            data = request.data
            features = data.get('features', {})
            
            if not features:
                return Response({
                    'status': 'error',
                    'message': 'Se requieren características de la URL'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Verificar si es un string JSON
            if isinstance(features, str):
                try:
                    features = json.loads(features)
                except:
                    return Response({
                        'status': 'error',
                        'message': 'Formato JSON inválido'
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            # Realizar predicción
            prediction, probability = predict_single_url(features)
            
            return Response({
                'status': 'success',
                'prediction': prediction,
                'probability': probability,
                'is_malicious': prediction == 'phishing'
            })
            
        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class BatchPredictView(APIView):
    def post(self, request):
        """Endpoint para predicción por lotes"""
        try:
            data = request.data
            urls_data = data.get('urls', [])
            
            # Si viene como string JSON, parsearlo
            if isinstance(urls_data, str):
                try:
                    urls_data = json.loads(urls_data)
                except json.JSONDecodeError:
                    # Intentar parsear como JSON lines
                    urls_data = []
                    for line in urls_data.split('\n'):
                        line = line.strip()
                        if line:
                            try:
                                urls_data.append(json.loads(line))
                            except:
                                continue
            
            if not urls_data:
                return Response({
                    'status': 'error',
                    'message': 'No se proporcionaron datos de URLs'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Realizar predicciones
            results = batch_predict(urls_data)
            
            # Calcular estadísticas
            successful = len([r for r in results if 'error' not in r])
            failed = len([r for r in results if 'error' in r])
            
            return Response({
                'status': 'success',
                'total': len(urls_data),
                'successful': successful,
                'failed': failed,
                'results': results
            })
            
        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ProcessFileView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    
    def post(self, request):
        try:
            file = request.FILES.get('file')
            
            if not file:
                return Response({
                    'status': 'error',
                    'message': 'No se proporcionó archivo'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Leer archivo
            content = file.read().decode('utf-8')
            urls_data = []
            
            # Detectar formato automáticamente
            try:
                # Intentar como JSON array
                data = json.loads(content)
                if isinstance(data, list):
                    urls_data = data
                else:
                    urls_data = [data]
                    
            except json.JSONDecodeError:
                # Intentar como JSON lines (un objeto por línea)
                lines = content.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if line:
                        try:
                            urls_data.append(json.loads(line))
                        except:
                            pass
                
                # Si no hay datos JSON, intentar como CSV
                if not urls_data:
                    csv_reader = csv.DictReader(io.StringIO(content))
                    for row in csv_reader:
                        processed_row = {}
                        for key, value in row.items():
                            key = key.strip()
                            if value and value.strip():
                                try:
                                    # Intentar convertir a número
                                    if '.' in value:
                                        processed_row[key] = float(value)
                                    else:
                                        processed_row[key] = int(value)
                                except:
                                    processed_row[key] = value
                            else:
                                processed_row[key] = 0.0
                        urls_data.append(processed_row)
            
            # Validar que tenemos datos
            if not urls_data:
                return Response({
                    'status': 'error',
                    'message': 'No se pudieron extraer datos del archivo'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Realizar predicciones
            results = batch_predict(urls_data)
            
            # Calcular estadísticas
            successful = len([r for r in results if 'error' not in r])
            failed = len([r for r in results if 'error' in r])
            
            # Contar benignas vs phishing
            benign_count = len([r for r in results if r.get('is_malicious') == False])
            phishing_count = len([r for r in results if r.get('is_malicious') == True])
            
            return Response({
                'status': 'success',
                'file_name': file.name,
                'file_size': len(content),
                'total_urls': len(urls_data),
                'successful': successful,
                'failed': failed,
                'benign_count': benign_count,
                'phishing_count': phishing_count,
                'results': results[:50]  # Limitar a 50 resultados para no sobrecargar
            })
            
        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ProcessDatasetView(APIView):
    def post(self, request):
        try:
            from .utils.model_processor import process_dataset
            
            # Procesar dataset
            results = process_dataset()
            
            if results['status'] == 'error':
                return Response(results, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            return Response(results)
            
        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ModelMetricsView(APIView):
    def get(self, request):
        try:
            from .utils.model_processor import get_model_metrics
            metrics = get_model_metrics()
            return Response({
                'status': 'success',
                'metrics': metrics
            })
        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)