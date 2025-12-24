// JavaScript básico para el frontend

document.addEventListener('DOMContentLoaded', function() {
    console.log('Sistema de Detección de URLs Maliciosas cargado');
    
    // Manejar formularios
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const btn = this.querySelector('button[type="submit"]');
            if (btn) {
                btn.innerHTML = '⏳ Procesando...';
                btn.disabled = true;
            }
        });
    });
    
    // Cargar métricas del modelo
    const metricsBtn = document.getElementById('load-metrics');
    if (metricsBtn) {
        metricsBtn.addEventListener('click', function() {
            loadModelMetrics();
        });
    }
});

async function loadModelMetrics() {
    try {
        const response = await fetch('/api/model-metrics/');
        const data = await response.json();
        
        if (data.status === 'success') {
            alert(`Métricas del Modelo SVM:\n\n` +
                  `📊 Precisión: ${(data.metrics.accuracy * 100).toFixed(2)}%\n` +
                  `🎯 Recall: ${(data.metrics.precision * 100).toFixed(2)}%\n` +
                  `⚡ F1-Score: ${(data.metrics.f1_score * 100).toFixed(2)}%`);
        } else {
            alert('Error al cargar métricas: ' + data.message);
        }
    } catch (error) {
        alert('Error de conexión: ' + error.message);
    }
}

// Función para predecir URL individual
async function predictURL(features) {
    try {
        const response = await fetch('/api/predict-url/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ features: features })
        });
        
        return await response.json();
    } catch (error) {
        return { status: 'error', message: error.message };
    }
}