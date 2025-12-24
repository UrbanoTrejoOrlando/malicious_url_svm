from django.shortcuts import render, redirect
import requests
import json
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

def index(request):
    """Página principal del frontend"""
    return render(request, 'frontend/index.html')

def results(request):
    """Página de resultados"""
    context = {}
    
    # Si se envió el formulario, procesar el dataset
    if request.method == 'POST':
        try:
            # Llamar a la API para procesar el dataset
            api_url = 'http://localhost:8000/api/process-dataset/'
            response = requests.post(api_url)
            
            if response.status_code == 200:
                data = response.json()
                context.update(data)
            else:
                context['error'] = 'Error al procesar el dataset'
                
        except Exception as e:
            context['error'] = str(e)
    
    return render(request, 'frontend/results.html', context)

def predict(request):
    """Página para cargar archivos y analizar URLs"""
    context = {}
    
    # Esta vista ahora solo renderiza el template
    # La lógica de procesamiento está en el frontend con JavaScript
    
    return render(request, 'frontend/predict.html', context)

def download_template(request, template_type):
    """Descargar plantillas de ejemplo"""
    from django.http import HttpResponse
    
    if template_type == 'csv':
        content = """domainUrlRatio,domainlength,Querylength,tld,NumberofDotsinURL,path_token_count,avgdomaintokenlen
0.157895,9,0,3,2,8,6.666666
0.511628,22,0,3,3,13,4.5"""
        
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
                "avgdomaintokenlen": 6.666666
            },
            {
                "domainUrlRatio": 0.511628,
                "domainlength": 22,
                "Querylength": 0,
                "tld": 3,
                "NumberofDotsinURL": 3,
                "path_token_count": 13,
                "avgdomaintokenlen": 4.5
            }
        ]
        
        response = HttpResponse(json.dumps(content, indent=2), content_type='application/json')
        response['Content-Disposition'] = 'attachment; filename="url_features_template.json"'
    
    else:
        return HttpResponse('Template no encontrado', status=404)
    
    return response

@csrf_exempt
def api_predict(request):
    """Endpoint de API para predicción (alternativa)"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            features = data.get('features', {})
            
            # Llamar al endpoint principal de la API
            api_url = 'http://localhost:8000/api/predict-url/'
            response = requests.post(api_url, json={'features': features})
            
            return JsonResponse(response.json())
            
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    return JsonResponse({
        'status': 'error',
        'message': 'Método no permitido'
    }, status=405)