# scripts/rebuild_model.py
import pandas as pd
import numpy as np
import joblib
import os
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import warnings
warnings.filterwarnings('ignore')

def rebuild_model():
    """Recrear el modelo y preprocesador con la estructura correcta"""
    print("🔄 Reconstruyendo modelo SVM...")
    
    # Rutas
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATASET_PATH = os.path.join(BASE_DIR, 'dataset', 'Phishing.csv')
    MODEL_DIR = os.path.join(BASE_DIR, 'ml_model')
    MODEL_PATH = os.path.join(MODEL_DIR, 'svm_model.pkl')
    PREPROCESSOR_PATH = os.path.join(MODEL_DIR, 'preprocessing.pkl')
    
    print(f"📊 Dataset: {DATASET_PATH}")
    print(f"💾 Modelo: {MODEL_PATH}")
    
    # 1. Cargar dataset
    print("📥 Cargando dataset...")
    df = pd.read_csv(DATASET_PATH)
    print(f"   Filas: {df.shape[0]}, Columnas: {df.shape[1]}")
    
    # 2. Preparar características
    if 'argPathRatio' in df.columns:
        df = df.drop('argPathRatio', axis=1)
    
    X = df.drop('URL_Type_obf_Type', axis=1)
    y = df['URL_Type_obf_Type'].copy()
    
    print(f"   Características (X): {X.shape}")
    print(f"   Etiquetas (y): {y.shape}")
    print(f"   Clases: {y.unique()}")
    
    # 3. Guardar las columnas (IMPORTANTE)
    all_columns = list(X.columns)
    print(f"   Número de columnas: {len(all_columns)}")
    print(f"   Primeras 5 columnas: {all_columns[:5]}")
    
    # 4. Crear preprocesador
    print("⚙️  Creando preprocesador...")
    imputer = SimpleImputer(strategy="median")
    X_prep = imputer.fit_transform(X)
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_prep)
    
    # 5. Dividir datos
    print("📊 Dividiendo datos...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.3, random_state=42, stratify=y
    )
    
    # 6. Entrenar modelo
    print("🤖 Entrenando modelo SVM...")
    svm_clf = SVC(kernel='linear', C=1.0, random_state=42, probability=True)
    svm_clf.fit(X_train, y_train)
    
    # 7. Evaluar
    y_pred = svm_clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"✅ Modelo entrenado. Precisión: {accuracy:.4f}")
    
    # 8. Guardar TODO
    print("💾 Guardando archivos...")
    os.makedirs(MODEL_DIR, exist_ok=True)
    
    # Guardar modelo
    joblib.dump(svm_clf, MODEL_PATH)
    print(f"   Modelo guardado en: {MODEL_PATH}")
    
    # Guardar preprocesador CON LAS COLUMNAS
    preprocessor_data = {
        'imputer': imputer,
        'scaler': scaler,
        'columns': all_columns  # ¡ESTO ES CRÍTICO!
    }
    joblib.dump(preprocessor_data, PREPROCESSOR_PATH)
    print(f"   Preprocesador guardado en: {PREPROCESSOR_PATH}")
    print(f"   Columnas incluidas: {len(all_columns)}")
    
    # 9. Verificar archivos
    model_size = os.path.getsize(MODEL_PATH) / 1024 / 1024
    preproc_size = os.path.getsize(PREPROCESSOR_PATH) / 1024
    print(f"📏 Tamaño modelo: {model_size:.2f} MB")
    print(f"📏 Tamaño preprocesador: {preproc_size:.1f} KB")
    
    # 10. Verificar que se pueden cargar
    print("🔍 Verificando carga...")
    loaded_model = joblib.load(MODEL_PATH)
    loaded_preproc = joblib.load(PREPROCESSOR_PATH)
    
    if 'columns' in loaded_preproc:
        print(f"✅ Preprocesador tiene {len(loaded_preproc['columns'])} columnas")
    else:
        print("❌ ERROR: Preprocesador no tiene columnas")
    
    print("🎉 Reconstrucción completada exitosamente!")
    return True

if __name__ == '__main__':
    rebuild_model()