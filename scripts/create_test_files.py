import json
import csv

def create_json_test_file():
    """Crear archivo JSON de prueba con formato correcto"""
    
    test_data = [
        {
            "domainUrlRatio": 0.157895,
            "domainlength": 9,
            "Querylength": 0,
            "tld": 3,
            "NumberofDotsinURL": 2,
            "path_token_count": 8,
            "avgdomaintokenlen": 6.666666,
            "charcompvowels": 11,
            "charcompace": 5,
            "urlLen": 47,
            # Características adicionales con valores por defecto
            "pathLength": 34,
            "subDirLen": 34,
            "fileNameLen": 0,
            "ArgLen": 0,
            "pathurlRatio": 0.723404,
            "executable": 0,
            "isPortEighty": 1,
            "CharacterContinuityRate": 1,
            "URL_DigitCount": 0,
            "URL_Letter_Count": 47
        },
        {
            "domainUrlRatio": 0.511628,
            "domainlength": 22,
            "Querylength": 0,
            "tld": 3,
            "NumberofDotsinURL": 3,
            "path_token_count": 13,
            "avgdomaintokenlen": 4.5,
            "charcompvowels": 24,
            "charcompace": 17,
            "urlLen": 66,
            # Características adicionales con valores por defecto
            "pathLength": 39,
            "subDirLen": 39,
            "fileNameLen": 0,
            "ArgLen": 16,
            "pathurlRatio": 0.590909,
            "executable": 0,
            "isPortEighty": 1,
            "CharacterContinuityRate": 0.795455,
            "URL_DigitCount": 5,
            "URL_Letter_Count": 41
        }
    ]
    
    # Guardar como JSON array
    with open('test_urls_array.json', 'w') as f:
        json.dump(test_data, f, indent=2)
    
    # Guardar como JSON lines
    with open('test_urls_lines.json', 'w') as f:
        for item in test_data:
            f.write(json.dumps(item) + '\n')
    
    # Guardar como CSV
    with open('test_urls.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=test_data[0].keys())
        writer.writeheader()
        writer.writerows(test_data)
    
    print("Archivos de prueba creados:")
    print("1. test_urls_array.json - Array JSON")
    print("2. test_urls_lines.json - JSON lines (un objeto por línea)")
    print("3. test_urls.csv - CSV")
    print("\nPuedes usar cualquiera de estos formatos.")

if __name__ == '__main__':
    create_json_test_file()