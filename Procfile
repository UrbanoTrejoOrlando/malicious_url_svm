web: gunicorn malicious_url_detector.wsgi:application --bind 0.0.0.0:$PORT
worker: python manage.py process_tasks  # Opcional para tareas background