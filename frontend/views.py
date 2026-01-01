from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
import json

# ============================================
# IMPORTAR FUNCIONES DIRECTAMENTE DESDE LA API
# ============================================
try:
    # Intentar importar las funciones del modelo
    from svm_api.utils.model_processor import (
        process_dataset, 
        predict_single_url, 
        batch_predict,
        get_model_metrics,
        prepare_features
    )
    API_AVAILABLE = True
    print("✅ Funciones del modelo importadas correctamente")
except ImportError as e:
    API_AVAILABLE = False
    print(f"⚠️ No se pudo importar las funciones del modelo: {e}")
    
    # Definir funciones dummy para modo simulación
    def process_dataset():
        """Función simulada para cuando no está disponible la API real"""
        print("📊 Usando datos de demostración (modo simulación)")
        return {
            'status': 'success',
            'metrics': {
                'accuracy': 0.956,
                'precision': 0.942,
                'recall': 0.968,
                'f1_score': 0.955,
                'confusion_matrix': [[8732, 49], [378, 9208]],
                'sample_size': 18367,
                'roc_auc': 0.984
            },
            'class_distribution': {
                'benign': 35300,
                'spam': 12000,
                'phishing': 10000,
                'malware': 11500,
                'total': 68800
            },
            'total_samples': 68800,
            'dataset_info': {
                'name': 'ISCX-URL2016',
                'description': 'Dataset de URLs para detección de amenazas web (modo simulación)',
                'url_types': 4,
                'features': 79,
                'year': 2016
            }
        }
    
    def predict_single_url(features_dict):
        """Función simulada de predicción"""
        print(f"🎯 Predicción simulada para {len(features_dict)} características")
        # Simular predicción basada en domainUrlRatio
        if 'domainUrlRatio' in features_dict:
            ratio = float(features_dict['domainUrlRatio'])
            if ratio > 0.7:
                return 'phishing', 0.92
            elif ratio > 0.4:
                return 'phishing' if ratio > 0.55 else 'benign', 0.67
            else:
                return 'benign', 0.85
        else:
            return 'benign', 0.78
    
    def batch_predict(urls_data):
        """Función simulada para predicción por lotes"""
        print(f"🎯 Predicción por lotes simulada para {len(urls_data)} URLs")
        results = []
        for i, features in enumerate(urls_data):
            prediction, probability = predict_single_url(features)
            results.append({
                'id': i + 1,
                'prediction': prediction,
                'probability': probability,
                'is_malicious': prediction == 'phishing',
                'confidence': 'alta' if probability > 0.8 else 'media' if probability > 0.6 else 'baja'
            })
        
        malicious_count = sum(1 for r in results if r['is_malicious'])
        
        return {
            'results': results,
            'statistics': {
                'total_urls': len(urls_data),
                'malicious_urls': malicious_count,
                'benign_urls': len(urls_data) - malicious_count,
                'malicious_percentage': (malicious_count / len(urls_data) * 100) if urls_data else 0
            }
        }
    
    def get_model_metrics():
        """Obtener métricas simuladas del modelo"""
        return process_dataset()['metrics']
    
    def prepare_features(features_dict):
        """Función simulada de preparación de características"""
        print(f"🔧 Preparando {len(features_dict)} características (simulado)")
        return {'simulated': True, 'features': features_dict}

# ============================================
# VISTAS DEL FRONTEND
# ============================================

def index(request):
    """Página principal del frontend"""
    context = {
        'api_available': API_AVAILABLE,
        'mode': 'Producción' if not request.get_host().startswith('localhost') else 'Desarrollo'
    }
    return render(request, 'frontend/index.html', context)

def results(request):
    """Página de resultados - LLAMADA DIRECTA A LAS FUNCIONES"""
    context = {}
    
    try:
        # Procesar el dataset directamente (sin HTTP)
        results_data = process_dataset()
        
        # Si es una llamada AJAX, devolver JSON
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse(results_data)
        
        # Si es una petición normal, renderizar template
        context.update(results_data)
        
    except Exception as e:
        error_msg = f'Error procesando dataset: {str(e)}'
        print(f"❌ {error_msg}")
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'status': 'error',
                'error': error_msg
            }, status=500)
        
        context['error'] = error_msg
        # Datos de demostración en caso de error
        context.update({
            'status': 'success',
            'metrics': {
                'accuracy': 0.95,
                'precision': 0.93,
                'recall': 0.96,
                'f1_score': 0.945,
            },
            'class_distribution': {
                'benign': 850,
                'phishing': 750,
            },
            'total_samples': 1600,
            'note': 'Datos de demostración (modo de respaldo)'
        })
    
    return render(request, 'frontend/results.html', context)

def predict(request):
    """Página para cargar archivos y analizar URLs"""
    context = {
        'api_available': API_AVAILABLE,
        'mode': 'simulación' if not API_AVAILABLE else 'producción'
    }
    return render(request, 'frontend/predict.html', context)

def download_template(request, template_type):
    """Descargar plantillas de ejemplo"""
    
    if template_type == 'csv':
        content = """domainUrlRatio,domainlength,Querylength,tld,NumberofDotsinURL,path_token_count,avgdomaintokenlen,Entropy_URL,domain_token_count
0.157895,9,0,3,2,8,6.666666,4.2,3
0.511628,22,0,3,3,13,4.5,3.8,5
0.321429,14,12,3,1,6,5.2,4.0,4
0.678571,28,0,3,4,15,4.8,3.5,6
0.432432,37,8,3,2,9,7.1,4.3,7"""
        
        response = HttpResponse(content, content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="url_features_template.csv"'
        
    elif template_type == 'json':
        content = [
            {
                "domainUrlRatio": 0.157895,
                "domainlength": 9,
                "Querylength": 0,
                "tld": 3,
                "NumberofDotsinURL": 2,
                "path_token_count": 8,
                "avgdomaintokenlen": 6.666666,
                "Entropy_URL": 4.2,
                "domain_token_count": 3
            },
            {
                "domainUrlRatio": 0.511628,
                "domainlength": 22,
                "Querylength": 0,
                "tld": 3,
                "NumberofDotsinURL": 3,
                "path_token_count": 13,
                "avgdomaintokenlen": 4.5,
                "Entropy_URL": 3.8,
                "domain_token_count": 5
            },
            {
                "domainUrlRatio": 0.321429,
                "domainlength": 14,
                "Querylength": 12,
                "tld": 3,
                "NumberofDotsinURL": 1,
                "path_token_count": 6,
                "avgdomaintokenlen": 5.2,
                "Entropy_URL": 4.0,
                "domain_token_count": 4
            }
        ]
        
        response = HttpResponse(json.dumps(content, indent=2), content_type='application/json')
        response['Content-Disposition'] = 'attachment; filename="url_features_template.json"'
    
    elif template_type == 'features_list':
        # Lista de todas las características disponibles
        features_list = [
            "Querylength", "domain_token_count", "path_token_count", "avgdomaintokenlen",
            "longdomaintokenlen", "avgpathtokenlen", "tld", "charcompvowels",
            "charcompace", "ldl_url", "ldl_domain", "ldl_path", "ldl_filename",
            "ldl_getArg", "dld_url", "dld_domain", "dld_path", "dld_filename",
            "dld_getArg", "urlLen", "domainlength", "pathLength", "subDirLen",
            "fileNameLen", "this.fileExtLen", "ArgLen", "pathurlRatio", "ArgUrlRatio",
            "argDomanRatio", "domainUrlRatio", "pathDomainRatio", "executable",
            "isPortEighty", "NumberofDotsinURL", "ISIpAddressInDomainName",
            "Entropy_URL", "Entropy_Domain", "Entropy_Path"
        ]
        
        content = "Características disponibles para análisis:\n\n" + "\n".join(features_list)
        response = HttpResponse(content, content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename="features_list.txt"'
    
    else:
        return HttpResponse('Template no encontrado', status=404)
    
    return response

# ============================================
# ENDPOINTS API INTERNOS
# ============================================

@csrf_exempt
def api_process_dataset(request):
    """Endpoint API para procesar dataset (para AJAX)"""
    if request.method == 'POST':
        try:
            # Procesar dataset directamente
            results = process_dataset()
            return JsonResponse(results)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'error': str(e),
                'mode': 'simulación' if not API_AVAILABLE else 'producción'
            }, status=500)
    
    # GET también funciona para obtener métricas
    elif request.method == 'GET':
        try:
            metrics = get_model_metrics()
            return JsonResponse({
                'status': 'success',
                'metrics': metrics,
                'api_available': API_AVAILABLE
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'error': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Método no permitido'}, status=405)

@csrf_exempt
def api_predict(request):
    """Endpoint API para predicción individual"""
    if request.method == 'POST':
        try:
            # Obtener datos JSON
            if request.content_type == 'application/json':
                data = json.loads(request.body)
            else:
                data = request.POST.dict()
            
            features = data.get('features', {})
            
            if not features:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Se requieren características de la URL'
                }, status=400)
            
            # Realizar predicción directamente
            prediction, probability = predict_single_url(features)
            
            return JsonResponse({
                'status': 'success',
                'prediction': prediction,
                'probability': probability,
                'is_malicious': prediction == 'phishing',
                'confidence': 'alta' if probability > 0.8 else 'media' if probability > 0.6 else 'baja',
                'api_available': API_AVAILABLE
            })
            
        except json.JSONDecodeError:
            return JsonResponse({
                'status': 'error',
                'message': 'Formato JSON inválido'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Método no permitido'}, status=405)

@csrf_exempt
def api_batch_predict(request):
    """Endpoint API para predicción por lotes"""
    if request.method == 'POST':
        try:
            # Obtener datos JSON
            if request.content_type == 'application/json':
                data = json.loads(request.body)
                urls_data = data.get('urls', [])
            else:
                # Intentar parsear como form-data
                urls_data_str = request.POST.get('urls', '[]')
                urls_data = json.loads(urls_data_str) if urls_data_str else []
            
            if not urls_data:
                return JsonResponse({
                    'status': 'error',
                    'message': 'No se proporcionaron URLs para analizar'
                }, status=400)
            
            # Realizar predicción por lotes directamente
            results = batch_predict(urls_data)
            results['status'] = 'success'
            results['api_available'] = API_AVAILABLE
            
            return JsonResponse(results)
            
        except json.JSONDecodeError:
            return JsonResponse({
                'status': 'error',
                'message': 'Formato JSON inválido'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Método no permitido'}, status=405)

@csrf_exempt
def api_process_file(request):
    """Endpoint API para procesar archivo CSV/JSON"""
    if request.method == 'POST':
        try:
            if 'file' not in request.FILES:
                return JsonResponse({
                    'status': 'error',
                    'message': 'No se proporcionó archivo'
                }, status=400)
            
            file = request.FILES['file']
            file_content = file.read().decode('utf-8')
            
            urls_data = []
            
            # Determinar tipo de archivo por extensión
            if file.name.lower().endswith('.csv'):
                import csv
                import io
                
                csv_reader = csv.DictReader(io.StringIO(file_content))
                for row in csv_reader:
                    # Convertir valores a float/int donde sea posible
                    processed_row = {}
                    for key, value in row.items():
                        try:
                            if '.' in value:
                                processed_row[key] = float(value)
                            else:
                                processed_row[key] = int(value)
                        except (ValueError, TypeError):
                            processed_row[key] = value
                    urls_data.append(processed_row)
                    
            elif file.name.lower().endswith('.json'):
                urls_data = json.loads(file_content)
                if not isinstance(urls_data, list):
                    urls_data = [urls_data]
            
            else:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Formato de archivo no soportado. Use CSV o JSON.'
                }, status=400)
            
            # Realizar predicción por lotes
            results = batch_predict(urls_data)
            results['status'] = 'success'
            results['filename'] = file.name
            results['file_size'] = len(file_content)
            results['api_available'] = API_AVAILABLE
            
            return JsonResponse(results)
            
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Método no permitido'}, status=405)

@csrf_exempt
def api_model_metrics(request):
    """Endpoint API para obtener métricas del modelo"""
    if request.method == 'GET':
        try:
            metrics = get_model_metrics()
            return JsonResponse({
                'status': 'success',
                'metrics': metrics,
                'api_available': API_AVAILABLE
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    return JsonResponse({'error': 'Método no permitido'}, status=405)

def api_docs(request):
    """Documentación de la API"""
    context = {
        'api_endpoints': [
            {
                'method': 'POST',
                'url': '/api/process-dataset/',
                'description': 'Procesar el dataset completo y generar métricas'
            },
            {
                'method': 'POST',
                'url': '/api/predict/',
                'description': 'Predecir una URL individual (enviar JSON con features)'
            },
            {
                'method': 'POST',
                'url': '/api/batch-predict/',
                'description': 'Predicción por lotes de múltiples URLs'
            },
            {
                'method': 'POST',
                'url': '/api/process-file/',
                'description': 'Procesar archivo CSV/JSON con URLs'
            },
            {
                'method': 'GET',
                'url': '/api/model-metrics/',
                'description': 'Obtener métricas del modelo'
            }
        ],
        'api_available': API_AVAILABLE
    }
    return render(request, 'frontend/api_docs.html', context)