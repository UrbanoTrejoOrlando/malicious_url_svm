import pandas as pd
import numpy as np
import joblib
import os
import matplotlib
matplotlib.use('Agg')  # Para usar matplotlib sin GUI
import matplotlib.pyplot as plt
import seaborn as sns
import base64
import io
import warnings
warnings.filterwarnings('ignore')
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
from django.conf import settings

# Cargar modelo si existe, o entrenar uno nuevo
MODEL_PATH = os.path.join(settings.BASE_DIR, 'ml_model/svm_model.pkl')
PREPROCESSOR_PATH = os.path.join(settings.BASE_DIR, 'ml_model/preprocessing.pkl')
DATASET_PATH = os.path.join(settings.BASE_DIR, 'dataset/Phishing.csv')

# Variables globales para las columnas
_ALL_COLUMNS = None
_MODEL = None
_PREPROCESSOR = None

def load_model_and_columns():
    """Cargar modelo y obtener columnas necesarias"""
    global _MODEL, _PREPROCESSOR, _ALL_COLUMNS
    
    if _MODEL is None or _PREPROCESSOR is None:
        if os.path.exists(MODEL_PATH) and os.path.exists(PREPROCESSOR_PATH):
            print("Cargando modelo existente...")
            _MODEL = joblib.load(MODEL_PATH)
            _PREPROCESSOR = joblib.load(PREPROCESSOR_PATH)
        else:
            print("Entrenando nuevo modelo...")
            _MODEL, _PREPROCESSOR = train_new_model()
    
    if _ALL_COLUMNS is None:
        _ALL_COLUMNS = get_all_columns()
    
    return _MODEL, _PREPROCESSOR, _ALL_COLUMNS

def get_all_columns():
    """Obtener todas las columnas del dataset original"""
    try:
        df = pd.read_csv(DATASET_PATH)
        # Excluir columnas que no son características
        columns = [col for col in df.columns 
                  if col not in ['URL_Type_obf_Type', 'argPathRatio']]
        
        print(f"Total de columnas necesarias: {len(columns)}")
        return columns
        
    except Exception as e:
        print(f"Error leyendo dataset: {e}")
        # Lista hardcoded como fallback
        return [
            'Querylength', 'domain_token_count', 'path_token_count', 
            'avgdomaintokenlen', 'longdomaintokenlen', 'avgpathtokenlen', 
            'tld', 'charcompvowels', 'charcompace', 'ldl_url', 'ldl_domain', 
            'ldl_path', 'ldl_filename', 'ldl_getArg', 'dld_url', 'dld_domain', 
            'dld_path', 'dld_filename', 'dld_getArg', 'urlLen', 'domainlength', 
            'pathLength', 'subDirLen', 'fileNameLen', 'this.fileExtLen', 'ArgLen', 
            'pathurlRatio', 'ArgUrlRatio', 'argDomanRatio', 'domainUrlRatio', 
            'pathDomainRatio', 'executable', 'isPortEighty', 'NumberofDotsinURL', 
            'ISIpAddressInDomainName', 'CharacterContinuityRate', 'LongestVariableValue', 
            'URL_DigitCount', 'host_DigitCount', 'Directory_DigitCount', 
            'File_name_DigitCount', 'Extension_DigitCount', 'Query_DigitCount', 
            'URL_Letter_Count', 'host_letter_count', 'Directory_LetterCount', 
            'Filename_LetterCount', 'Extension_LetterCount', 'Query_LetterCount', 
            'LongestPathTokenLength', 'Domain_LongestWordLength', 'Path_LongestWordLength', 
            'sub-Directory_LongestWordLength', 'Arguments_LongestWordLength', 
            'URL_sensitiveWord', 'URLQueries_variable', 'spcharUrl', 'delimeter_Domain', 
            'delimeter_path', 'delimeter_Count', 'NumberRate_URL', 'NumberRate_Domain', 
            'NumberRate_DirectoryName', 'NumberRate_FileName', 'NumberRate_Extension', 
            'NumberRate_AfterPath', 'SymbolCount_URL', 'SymbolCount_Domain', 
            'SymbolCount_Directoryname', 'SymbolCount_FileName', 'SymbolCount_Extension', 
            'SymbolCount_Afterpath', 'Entropy_URL', 'Entropy_Domain', 
            'Entropy_DirectoryName', 'Entropy_Filename', 'Entropy_Extension', 
            'Entropy_Afterpath'
        ]

def prepare_features(features_dict):
    """Preparar características completando con valores por defecto"""
    model, preprocessor, all_columns = load_model_and_columns()
    
    # Crear DataFrame con todas las columnas necesarias
    features_df = pd.DataFrame(columns=all_columns)
    
    # Añadir las características proporcionadas
    for key, value in features_dict.items():
        if key in all_columns:
            features_df[key] = [value]
    
    # Completar valores faltantes con 0 (o valores por defecto apropiados)
    for col in all_columns:
        if col not in features_df.columns:
            # Valores por defecto específicos para ciertas columnas
            if 'Entropy' in col:
                features_df[col] = [-1.0]  # Valor por defecto para entropía
            elif 'Ratio' in col or col in ['domainUrlRatio', 'pathurlRatio', 'ArgUrlRatio']:
                features_df[col] = [0.0]
            elif col in ['ldl_url', 'ldl_domain', 'ldl_path', 'ldl_filename', 'ldl_getArg',
                        'dld_url', 'dld_domain', 'dld_path', 'dld_filename', 'dld_getArg']:
                features_df[col] = [0.0]
            elif col in ['executable', 'isPortEighty', 'ISIpAddressInDomainName']:
                features_df[col] = [0]
            else:
                features_df[col] = [0.0]  # Valor por defecto general
    
    # Asegurar el orden correcto de columnas
    features_df = features_df[all_columns]
    
    return features_df

def train_new_model():
    """Entrenar un nuevo modelo SVM"""
    print("Entrenando nuevo modelo SVM...")
    
    # Cargar datos
    df = pd.read_csv(DATASET_PATH)
    
    # Excluir columnas no deseadas
    if 'argPathRatio' in df.columns:
        df = df.drop('argPathRatio', axis=1)
    
    # Preparar características
    X = df.drop('URL_Type_obf_Type', axis=1)
    y = df['URL_Type_obf_Type'].copy()
    
    # Guardar columnas
    global _ALL_COLUMNS
    _ALL_COLUMNS = list(X.columns)
    print(f"Columnas del modelo: {len(_ALL_COLUMNS)}")
    
    # Rellenar valores nulos
    from sklearn.impute import SimpleImputer
    imputer = SimpleImputer(strategy="median")
    X_prep = imputer.fit_transform(X)
    X_prep = pd.DataFrame(X_prep, columns=X.columns)
    
    # Escalar características
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_prep)
    
    # Dividir datos
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.3, random_state=42, stratify=y
    )
    
    # Entrenar modelo
    svm_clf = SVC(kernel='linear', C=1.0, random_state=42, probability=True)
    svm_clf.fit(X_train, y_train)
    
    # Evaluar
    y_pred = svm_clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Modelo entrenado. Precisión: {accuracy:.4f}")
    
    # Guardar
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(svm_clf, MODEL_PATH)
    joblib.dump({'imputer': imputer, 'scaler': scaler, 'columns': _ALL_COLUMNS}, PREPROCESSOR_PATH)
    
    return svm_clf, {'imputer': imputer, 'scaler': scaler}

def predict_single_url(features_dict):
    """Predecir si una URL es maliciosa"""
    try:
        print(f"Recibiendo predicción para características: {list(features_dict.keys())}")
        
        # Cargar modelo y preprocesador
        model, preprocessor, all_columns = load_model_and_columns()
        
        # Preparar características
        features_df = prepare_features(features_dict)
        
        print(f"DataFrame preparado con shape: {features_df.shape}")
        print(f"Columnas: {len(features_df.columns)}")
        
        # Verificar que tenemos todas las columnas necesarias
        missing_cols = set(all_columns) - set(features_df.columns)
        if missing_cols:
            print(f"Advertencia: Columnas faltantes: {missing_cols}")
        
        # Aplicar preprocesamiento
        features_prep = preprocessor['imputer'].transform(features_df)
        features_scaled = preprocessor['scaler'].transform(features_prep)
        
        print(f"Forma después de preprocesamiento: {features_scaled.shape}")
        
        # Predecir
        prediction = model.predict(features_scaled)[0]
        probabilities = model.predict_proba(features_scaled)[0]
        
        # Obtener probabilidad de phishing
        class_labels = list(model.classes_)
        phishing_idx = class_labels.index('phishing') if 'phishing' in class_labels else 1
        
        probability = float(probabilities[phishing_idx])
        
        print(f"Predicción: {prediction}, Probabilidad: {probability}")
        
        return prediction, probability
        
    except Exception as e:
        print(f"Error detallado en predict_single_url: {str(e)}")
        import traceback
        traceback.print_exc()
        raise

def process_dataset():
    """Procesar dataset completo"""
    try:
        print("Procesando dataset completo...")
        
        # Cargar modelo
        model, preprocessor, all_columns = load_model_and_columns()
        
        # Cargar datos
        df = pd.read_csv(DATASET_PATH)
        
        if 'argPathRatio' in df.columns:
            df = df.drop('argPathRatio', axis=1)
        
        X = df.drop('URL_Type_obf_Type', axis=1)
        y = df['URL_Type_obf_Type'].copy()
        
        # Aplicar preprocesamiento
        X_prep = preprocessor['imputer'].transform(X)
        X_scaled = preprocessor['scaler'].transform(X_prep)
        
        # Dividir y predecir
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.3, random_state=42, stratify=y
        )
        
        y_pred = model.predict(X_test)
        
        # Calcular métricas
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, pos_label='phishing')
        recall = recall_score(y_test, y_pred, pos_label='phishing')
        f1 = f1_score(y_test, y_pred, pos_label='phishing')
        cm = confusion_matrix(y_test, y_pred, labels=['benign', 'phishing'])
        
        # Distribución
        class_dist = y.value_counts().to_dict()
        
        return {
            'status': 'success',
            'metrics': {
                'accuracy': float(accuracy),
                'precision': float(precision),
                'recall': float(recall),
                'f1_score': float(f1),
                'confusion_matrix': cm.tolist()
            },
            'class_distribution': class_dist,
            'predictions_count': len(y_pred)
        }
        
    except Exception as e:
        print(f"Error en process_dataset: {e}")
        raise

def get_model_metrics():
    """Obtener métricas del modelo"""
    return process_dataset()['metrics']

def batch_predict(urls_data):
    """Predicción por lotes"""
    results = []
    
    for i, features in enumerate(urls_data):
        try:
            prediction, probability = predict_single_url(features)
            results.append({
                'id': i + 1,
                'prediction': prediction,
                'probability': probability,
                'is_malicious': prediction == 'phishing'
            })
        except Exception as e:
            results.append({
                'id': i + 1,
                'error': str(e)
            })
    
    return results

def generate_decision_boundary_plot():
    """Generar gráfica de límite de decisión exactamente como en el Jupyter notebook"""
    try:
        # Cargar dataset
        df = pd.read_csv(DATASET_PATH)
        
        # Usar las mismas características que en el notebook
        features_2d = ["domainUrlRatio", "domainlength"]
        
        if not all(feat in df.columns for feat in features_2d):
            print("Características para límite de decisión no encontradas, usando alternativas")
            return None
        
        # Preparar datos como en el notebook
        X_2d = df[features_2d].copy()
        y_2d = df["URL_Type_obf_Type"].copy()
        
        # Limitar a un subconjunto para mejor visualización (como en el notebook reducido)
        sample_size = min(200, len(X_2d))
        X_sampled = X_2d.sample(sample_size, random_state=42)
        y_sampled = y_2d.loc[X_sampled.index]
        
        # Separar por clases
        X_benign = X_sampled[y_sampled == 'benign']
        X_phishing = X_sampled[y_sampled == 'phishing']
        
        # Crear figura con el mismo estilo que el notebook
        plt.figure(figsize=(12, 8))
        
        # Puntos benignos (verde, puntos)
        plt.scatter(X_benign[features_2d[0]], X_benign[features_2d[1]], 
                   c="green", marker=".", s=50, alpha=0.7, label="Benignas")
        
        # Puntos phishing (rojo, cruces)
        plt.scatter(X_phishing[features_2d[0]], X_phishing[features_2d[1]], 
                   c="red", marker="x", s=50, alpha=0.7, label="Phishing")
        
        # Entrenar un SVM lineal solo con estas 2 características para visualización
        from sklearn.svm import SVC
        svm_2d = SVC(kernel='linear', C=1.0, random_state=42)
        svm_2d.fit(X_sampled, y_sampled)
        
        # Obtener parámetros del modelo como en el notebook
        w = svm_2d.coef_[0]
        b = svm_2d.intercept_[0]
        
        # Calcular límite de decisión como en plot_svc_decision_boundary()
        x_min, x_max = X_sampled[features_2d[0]].min() - 0.1, X_sampled[features_2d[0]].max() + 0.1
        x0 = np.linspace(x_min, x_max, 200)
        
        # Línea de decisión: w0*x0 + w1*x1 + b = 0 => x1 = -w0/w1 * x0 - b/w1
        decision_boundary = -w[0]/w[1] * x0 - b/w[1]
        
        # Margen: 1/w[1]
        margin = 1/np.sqrt(np.sum(svm_2d.coef_ ** 2))
        gutter_up = decision_boundary + margin
        gutter_down = decision_boundary - margin
        
        # Dibujar línea de decisión
        plt.plot(x0, decision_boundary, "k-", linewidth=3, label="Límite de Decisión")
        
        # Dibujar márgenes
        plt.plot(x0, gutter_up, "k--", linewidth=2, alpha=0.5, label="Margen")
        plt.plot(x0, gutter_down, "k--", linewidth=2, alpha=0.5)
        
        # Dibujar vectores de soporte
        if hasattr(svm_2d, 'support_vectors_'):
            svs = svm_2d.support_vectors_
            plt.scatter(svs[:, 0], svs[:, 1], s=180, facecolors='none', 
                       edgecolors='blue', linewidths=2, label="Vectores de Soporte")
        
        # Configurar el gráfico como en el notebook
        plt.title("Límite de Decisión SVM - domainUrlRatio vs domainlength", 
                 fontsize=16, fontweight='bold', pad=20)
        plt.xlabel(features_2d[0], fontsize=14)
        plt.ylabel(features_2d[1], fontsize=14)
        
        # Añadir grid y leyenda
        plt.grid(True, alpha=0.3, linestyle='--')
        plt.legend(loc='best', fontsize=12)
        
        # Ajustar límites
        plt.xlim(x_min, x_max)
        y_min, y_max = X_sampled[features_2d[1]].min() - 5, X_sampled[features_2d[1]].max() + 5
        plt.ylim(y_min, y_max)
        
        # Añadir anotación con información del modelo
        plt.text(0.02, 0.98, f'Modelo SVM Lineal\nVectores de soporte: {len(svm_2d.support_vectors_) if hasattr(svm_2d, "support_vectors_") else "N/A"}',
                transform=plt.gca().transAxes,
                verticalalignment='top',
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5),
                fontsize=10)
        
        # Convertir a base64
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=120, bbox_inches='tight', facecolor='white')
        plt.close()
        buf.seek(0)
        image_base64 = base64.b64encode(buf.read()).decode('utf-8')
        buf.close()
        
        print("✅ Gráfica de límite de decisión generada correctamente")
        return image_base64
        
    except Exception as e:
        print(f"❌ Error generando gráfica de límite de decisión: {e}")
        import traceback
        traceback.print_exc()
        return None

def generate_class_distribution_plot(class_dist):
    """Generar gráfica de distribución de clases"""
    try:
        plt.figure(figsize=(10, 6))
        
        colors = ['green', 'red']
        bars = plt.bar(class_dist.keys(), class_dist.values(), color=colors)
        
        plt.title('Distribución de URLs (Benignas vs Phishing)')
        plt.xlabel('Tipo de URL')
        plt.ylabel('Cantidad')
        plt.xticks(rotation=0)
        
        # Añadir valores en las barras
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 50,
                    f'{int(height)}', ha='center', va='bottom')
        
        # Convertir a base64
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
        plt.close()
        buf.seek(0)
        image_base64 = base64.b64encode(buf.read()).decode('utf-8')
        buf.close()
        
        return image_base64
        
    except Exception as e:
        print(f"Error generando gráfica de distribución: {e}")
        return None

def generate_confusion_matrix_plot(cm):
    """Generar gráfica de matriz de confusión"""
    try:
        plt.figure(figsize=(8, 6))
        
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=['Benign', 'Phishing'],
                   yticklabels=['Benign', 'Phishing'])
        
        plt.title('Matriz de Confusión')
        plt.ylabel('Verdadero')
        plt.xlabel('Predicho')
        
        # Convertir a base64
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
        plt.close()
        buf.seek(0)
        image_base64 = base64.b64encode(buf.read()).decode('utf-8')
        buf.close()
        
        return image_base64
        
    except Exception as e:
        print(f"Error generando matriz de confusión: {e}")
        return None

def generate_metrics_plot(metrics):
    """Generar gráfica de métricas"""
    try:
        plt.figure(figsize=(10, 6))
        
        metric_names = ['Precisión', 'Recall', 'F1-Score', 'Accuracy']
        metric_values = [
            metrics.get('precision', 0),
            metrics.get('recall', 0),
            metrics.get('f1_score', 0),
            metrics.get('accuracy', 0)
        ]
        
        colors = ['skyblue', 'lightgreen', 'lightcoral', 'gold']
        bars = plt.bar(metric_names, metric_values, color=colors)
        
        plt.title('Métricas del Modelo SVM')
        plt.ylabel('Valor')
        plt.ylim(0, 1.1)
        
        # Añadir valores en las barras
        for bar, value in zip(bars, metric_values):
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.02,
                    f'{value:.3f}', ha='center', va='bottom')
        
        # Convertir a base64
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
        plt.close()
        buf.seek(0)
        image_base64 = base64.b64encode(buf.read()).decode('utf-8')
        buf.close()
        
        return image_base64
        
    except Exception as e:
        print(f"Error generando gráfica de métricas: {e}")
        return None

def process_dataset():
    """Procesar dataset completo con gráficas"""
    try:
        print("Procesando dataset completo...")
        
        # Cargar modelo
        model, preprocessor, all_columns = load_model_and_columns()
        
        # Cargar datos
        df = pd.read_csv(DATASET_PATH)
        
        if 'argPathRatio' in df.columns:
            df = df.drop('argPathRatio', axis=1)
        
        X = df.drop('URL_Type_obf_Type', axis=1)
        y = df['URL_Type_obf_Type'].copy()
        
        # Aplicar preprocesamiento
        X_prep = preprocessor['imputer'].transform(X)
        X_scaled = preprocessor['scaler'].transform(X_prep)
        
        # Dividir y predecir
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.3, random_state=42, stratify=y
        )
        
        y_pred = model.predict(X_test)
        
        # Calcular métricas
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, pos_label='phishing')
        recall = recall_score(y_test, y_pred, pos_label='phishing')
        f1 = f1_score(y_test, y_pred, pos_label='phishing')
        cm = confusion_matrix(y_test, y_pred, labels=['benign', 'phishing'])
        
        # Distribución
        class_dist = y.value_counts().to_dict()
        
        # Generar gráficas
        print("Generando gráficas...")
        
        # Intentar con la gráfica detallada primero
        decision_boundary_graph = generate_decision_boundary_plot()
        
        # Si falla, usar la versión simplificada
        if decision_boundary_graph is None:
            print("Usando versión simplificada de la gráfica de límite de decisión")
            decision_boundary_graph = generate_simple_decision_boundary()
        
        graphs = {
            'class_distribution': generate_class_distribution_plot(class_dist),
            'confusion_matrix': generate_confusion_matrix_plot(cm),
            'model_metrics': generate_metrics_plot({
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1
            }),
            'decision_boundary': decision_boundary_graph
        }
        
        # Remover gráficas None
        graphs = {k: v for k, v in graphs.items() if v is not None}
        
        print(f"Gráficas generadas: {list(graphs.keys())}")
        
        return {
            'status': 'success',
            'metrics': {
                'accuracy': float(accuracy),
                'precision': float(precision),
                'recall': float(recall),
                'f1_score': float(f1),
                'confusion_matrix': cm.tolist()
            },
            'class_distribution': class_dist,
            'predictions_count': len(y_pred),
            'total_samples': len(df),
            'graphs': graphs
        }
        
    except Exception as e:
        print(f"Error en process_dataset: {e}")
        import traceback
        traceback.print_exc()
        return {
            'status': 'error',
            'message': str(e)
        }