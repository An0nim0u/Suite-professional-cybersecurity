import dns.query
import dns.zone
import dns.resolver
import socket
import time
import csv
import json
from urllib.parse import urlparse
import threading
import requests

# Configuración básica
DOMAINS_TO_CHECK = ["example.com", "example.org", "example.net"]
DNS_SERVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]  # Servidores DNS comunes para pruebas
OUTPUT_JSON = "axfr_results.json"
OUTPUT_CSV = "axfr_results.csv"
TIMEOUT = 5  # Timeout en segundos
MAX_THREADS = 10  # Máximo de hilos para realizar consultas paralelas

# URL de crt.sh para buscar subdominios de un dominio
CRT_SH_API = "https://crt.sh/?q=%25{domain}&output=json"

# Función para realizar AXFR (Transferencia de zona)
def perform_axfr(domain, dns_server):
    """Realiza un intento de transferencia de zona AXFR en un servidor DNS."""
    try:
        # Realizar la consulta AXFR al servidor DNS
        zone = dns.zone.from_xfr(dns.query.xfr(dns_server, domain))
        print(f"[✅] Transferencia de zona exitosa para {domain} en {dns_server}")
        
        # Extraer los registros obtenidos
        records = []
        for name, node in zone.nodes.items():
            rdataset = node.rdatasets
            for rdata in rdataset:
                for r in rdata:
                    records.append(f"{name} {r}")
        
        return {"domain": domain, "dns_server": dns_server, "records": records, "vulnerable": True}
    
    except Exception as e:
        print(f"[❌] Error al intentar AXFR en {domain} con {dns_server}: {e}")
        return {"domain": domain, "dns_server": dns_server, "records": [], "vulnerable": False}

# Función para obtener los servidores DNS de un dominio
def get_dns_servers(domain):
    """Obtiene los servidores DNS para un dominio utilizando consultas DNS."""
    try:
        resolver = dns.resolver.Resolver()
        answer = resolver.resolve(domain, 'NS')
        dns_servers = [str(rdata.target).rstrip('.') for rdata in answer]
        return dns_servers
    except dns.resolver.NoAnswer as e:
        print(f"[ERROR] No se pudo obtener servidores DNS para {domain}: {e}")
        return []

# Función para obtener subdominios desde crt.sh
def get_subdomains_from_crtsh(domain):
    """Obtiene subdominios de un dominio usando el servicio crt.sh."""
    url = CRT_SH_API.format(domain=domain)
    try:
        response = requests.get(url, timeout=TIMEOUT)
        subdomains = [entry['name_value'] for entry in response.json()]
        print(f"[🔍] Subdominios encontrados para {domain}: {subdomains}")
        return subdomains
    except Exception as e:
        print(f"[❌] Error al obtener subdominios desde crt.sh para {domain}: {e}")
        return []

# Función para escanear un dominio para AXFR
def scan_for_axfr(domain):
    """Escanea un dominio y prueba la transferencia de zona AXFR en sus servidores DNS."""
    print(f"[🔍] Escaneando dominio {domain} para AXFR...")
    
    # Obtener servidores DNS del dominio
    dns_servers = get_dns_servers(domain)
    
    if not dns_servers:
        print(f"[❌] No se encontraron servidores DNS para {domain}.")
        return []
    
    results = []
    
    # Probar AXFR en los servidores DNS encontrados
    for dns_server in dns_servers:
        for server in DNS_SERVERS:
            result = perform_axfr(domain, server)
            if result["vulnerable"]:
                results.append(result)
    
    # Obtener subdominios relacionados con el dominio
    subdomains = get_subdomains_from_crtsh(domain)
    
    # Realizar AXFR en los subdominios encontrados
    for subdomain in subdomains:
        for server in DNS_SERVERS:
            result = perform_axfr(subdomain, server)
            if result["vulnerable"]:
                results.append(result)
    
    return results

# Función para evaluar el impacto de los registros DNS obtenidos
def evaluate_impact(records):
    """Clasifica los registros DNS y evalúa el impacto de la transferencia de zona."""
    critical_records = []
    high_priority_records = []
    low_priority_records = []
    
    for record in records:
        if "A" in record or "MX" in record or "TXT" in record:
            critical_records.append(record)
        elif "NS" in record:
            high_priority_records.append(record)
        else:
            low_priority_records.append(record)
    
    return {
        "critical": critical_records,
        "high_priority": high_priority_records,
        "low_priority": low_priority_records
    }

# Función para generar el reporte en JSON
def generate_json_report(results):
    """Genera un reporte en formato JSON con los resultados de las transferencias de zona."""
    with open(OUTPUT_JSON, "w") as json_file:
        json.dump(results, json_file, indent=4)
    print(f"[📄] Reporte generado en formato JSON: {OUTPUT_JSON}")

# Función para generar el reporte en CSV
def generate_csv_report(results):
    """Genera un reporte en formato CSV con los resultados de las transferencias de zona."""
    with open(OUTPUT_CSV, "w", newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Domain", "DNS Server", "Record", "Vulnerable", "Impact"])
        
        for result in results:
            if result["vulnerable"]:
                for record in result["records"]:
                    impact = "Critical" if "A" in record or "MX" in record or "TXT" in record else "High"
                    writer.writerow([result["domain"], result["dns_server"], record, "Yes", impact])
            else:
                writer.writerow([result["domain"], result["dns_server"], "N/A", "No", "Low"])
    
    print(f"[📄] Reporte generado en formato CSV: {OUTPUT_CSV}")

# Función para paralelizar el escaneo con hilos
def scan_domains_parallel(domains):
    """Escanea múltiples dominios en paralelo utilizando hilos."""
    threads = []
    results = []
    
    # Función para manejar los resultados de cada hilo
    def thread_func(domain):
        nonlocal results
        result = scan_for_axfr(domain)
        if result:
            results.extend(result)
    
    # Crear y arrancar los hilos
    for domain in domains:
        thread = threading.Thread(target=thread_func, args=(domain,))
        threads.append(thread)
        thread.start()
    
    # Esperar a que todos los hilos terminen
    for thread in threads:
        thread.join()
    
    return results

# Función principal
def main():
    # Escanear todos los dominios en paralelo
    print("[🔍] Iniciando el escaneo AXFR para los dominios.")
    results = scan_domains_parallel(DOMAINS_TO_CHECK)
    
    # Evaluar el impacto de los registros obtenidos
    for result in results:
        if result["vulnerable"]:
            impact = evaluate_impact(result["records"])
            result["impact"] = impact
    
    # Generar los reportes en JSON y CSV
    if results:
        generate_json_report(results)
        generate_csv_report(results)
    else:
        print("[❌] No se encontraron vulnerabilidades de AXFR.")

if __name__ == "__main__":
    main()
