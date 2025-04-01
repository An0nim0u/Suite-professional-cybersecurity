import socket
import dns.resolver
import dns.message
import time
import random
import threading
import logging
import platform
import json
import csv
import sys
import os
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

# Configuración de logging para un análisis más detallado
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Funciones básicas del sistema
def get_os_info():
    """Obtiene información del sistema operativo."""
    os_name = platform.system()
    os_version = platform.release()
    return f"{os_name} {os_version}"

def get_python_version():
    """Obtiene la versión de Python."""
    return platform.python_version()

# Validaciones de seguridad
def check_authorization():
    """Valida que el script se ejecute solo en entornos autorizados con consentimiento explícito."""
    authorized_ips = ["192.168.1.100", "10.0.0.5"]  # Lista de IPs autorizadas
    user_ip = socket.gethostbyname(socket.gethostname())
    if user_ip not in authorized_ips:
        logging.critical(f"Acceso no autorizado desde IP {user_ip}. El script no se ejecutará.")
        sys.exit("Acceso no autorizado.")
    logging.info(f"Acceso autorizado desde la IP {user_ip}. El script continuará.")

def get_user_consent():
    """Solicita el consentimiento explícito del usuario para realizar las pruebas éticas."""
    consent = input("¿Estás autorizado para realizar pruebas de seguridad en este entorno? (s/n): ")
    if consent.lower() != 's':
        logging.critical("No se obtuvo el consentimiento. El script se detiene.")
        sys.exit("Sin consentimiento explícito.")
    logging.info("Consentimiento obtenido. Procediendo con las pruebas.")

# Función para obtener servidores DNS
def get_dns_servers(url):
    """Obtiene los servidores DNS de una URL."""
    try:
        domain = url.split("//")[-1].split("/")[0]
        answers = dns.resolver.resolve(domain, "NS")
        return [str(rdata) for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, IndexError):
        logging.error("Error al obtener servidores DNS.")
        return []

# Análisis de amplificación DNS
def check_dns_amplification(dns_server):
    """Verifica la vulnerabilidad de amplificación DNS."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        query = dns.message.make_query("ANY google.com", dns.rdatatype.ANY)
        response = resolver.resolve(query)
        query_size = len(query.to_wire())
        response_size = len(response.to_wire())
        amplification_factor = response_size / query_size
        return amplification_factor > 10
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
        logging.error(f"Error al verificar amplificación DNS en {dns_server}: {e}")
        return False

# Analizar vulnerabilidades DoS en DNS
def check_dns_dos_vulnerabilities(dns_server):
    """Verifica vulnerabilidades DoS en un servidor DNS."""
    vulnerabilities = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]

        # Vulnerabilidad a ataques de inundación de consultas DNS
        for _ in range(100):
            resolver.resolve(f"random_query_{random.randint(1, 100000)}.com", "A")
        vulnerabilities.append("DNS Query Flood")
    except dns.resolver.Timeout:
        vulnerabilities.append("DNS Query Flood")  # Si hay timeout, es vulnerable

    # Vulnerabilidad a ataques de inundación de respuestas DNS
    try:
        resolver.resolve("ANY google.com", "ANY")
    except dns.resolver.Timeout:
        vulnerabilities.append("DNS Response Flood")
    
    # Verifica amplificación DNS
    if check_dns_amplification(dns_server):
        vulnerabilities.append("DNS Amplification")

    # Vulnerabilidad a ataques de inundación de subdominios aleatorios
    try:
        for _ in range(100):
            resolver.resolve(f"{random.randint(1, 100000)}.random.google.com", "A")
    except dns.resolver.Timeout:
        vulnerabilities.append("Random Subdomain Flood")

    return vulnerabilities

# Función para realizar un análisis de DNS completo
def analyze_dns(url):
    """Analiza las vulnerabilidades DoS de los servidores DNS de una URL."""
    dns_servers = get_dns_servers(url)
    if not dns_servers:
        logging.warning("No se encontraron servidores DNS para la URL proporcionada.")
        return

    logging.info(f"Servidores DNS encontrados para {url}: {', '.join(dns_servers)}")
    dns_results = {}
    response_times = []
    for dns_server in dns_servers:
        start_time = time.time()
        logging.info(f"\nAnalizando servidor DNS: {dns_server}")
        vulnerabilities = check_dns_dos_vulnerabilities(dns_server)
        end_time = time.time()
        response_time = end_time - start_time
        response_times.append(response_time)
        dns_results[dns_server] = {
            "vulnerabilities": vulnerabilities,
            "response_time": response_time
        }

    generate_report(url, dns_results, response_times)

# Funciones para la generación de informes
def generate_report(url, dns_results, response_times):
    """Genera un informe detallado sobre las vulnerabilidades encontradas en los servidores DNS."""
    logging.info(f"\nGenerando informe para {url}...")
    report = {
        "url": url,
        "dns_results": dns_results
    }
    print("\n=== Informe Completo ===")
    print(f"Análisis de servidores DNS para: {url}")
    for dns_server, result in dns_results.items():
        print(f"\nServidor DNS: {dns_server}")
        if result["vulnerabilities"]:
            print(f"Vulnerabilidades detectadas: {', '.join(result['vulnerabilities'])}")
        else:
            print("No se detectaron vulnerabilidades.")
        print(f"Tiempo de respuesta: {result['response_time']:.4f} segundos")
    
    # Estadísticas y gráficas
    generate_statistics(response_times)

    # Exportar a formatos JSON y CSV
    export_to_json(report)
    export_to_csv(report)

def generate_statistics(response_times):
    """Genera estadísticas y una gráfica de los tiempos de respuesta."""
    if response_times:
        avg_time = np.mean(response_times)
        max_time = np.max(response_times)
        min_time = np.min(response_times)
        print(f"\nEstadísticas de tiempo de respuesta:")
        print(f"Promedio: {avg_time:.4f} segundos")
        print(f"Máximo: {max_time:.4f} segundos")
        print(f"Mínimo: {min_time:.4f} segundos")
        
        # Generación de gráfico de barras
        plt.figure(figsize=(10, 6))
        plt.bar(range(len(response_times)), response_times, color='skyblue')
        plt.title('Tiempos de Respuesta por Servidor DNS')
        plt.xlabel('Servidor DNS')
        plt.ylabel('Tiempo de Respuesta (segundos)')
        plt.xticks(range(len(response_times)), [f"DNS-{i+1}" for i in range(len(response_times))])
        plt.tight_layout()
        plt.show()

def export_to_json(report, filename="dns_report.json"):
    """Exporta el informe a un archivo JSON."""
    try:
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
        logging.info(f"Informe exportado a {filename}.")
    except Exception as e:
        logging.error(f"Error al exportar a JSON: {e}")

def export_to_csv(report, filename="dns_report.csv"):
    """Exporta el informe a un archivo CSV."""
    try:
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Servidor DNS", "Vulnerabilidades", "Tiempo de Respuesta (segundos)"])
            for dns_server, result in report["dns_results"].items():
                writer.writerow([dns_server, ", ".join(result["vulnerabilities"]) if result["vulnerabilities"] else "Ninguna", result["response_time"]])
        logging.info(f"Informe exportado a {filename}.")
    except Exception as e:
        logging.error(f"Error al exportar a CSV: {e}")

# Funciones de análisis avanzadas
def dns_stress_test(dns_server, test_count=500):
    """Realiza una prueba de estrés sobre un servidor DNS."""
    logging.info(f"Iniciando prueba de estrés sobre el servidor DNS {dns_server}...")
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]
    failed_requests = 0

    for _ in range(test_count):
        try:
            resolver.resolve(f"test{random.randint(1, 100000)}.com", "A")
        except dns.resolver.Timeout:
            failed_requests += 1

    if failed_requests > (test_count / 2):
        logging.warning(f"El servidor DNS {dns_server} es susceptible a un ataque de estrés. Fallaron {failed_requests} de {test_count} peticiones.")
    else:
        logging.info(f"El servidor DNS {dns_server} soportó la prueba de estrés correctamente.")

def concurrent_dns_analysis(url):
    """Analiza de manera concurrente los servidores DNS de la URL proporcionada."""
    dns_servers = get_dns_servers(url)
    if not dns_servers:
        logging.warning("No se encontraron servidores DNS para la URL proporcionada.")
        return

    logging.info(f"Analizando concurrentemente los servidores DNS para {url}...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(check_dns_dos_vulnerabilities, dns_server): dns_server for dns_server in dns_servers}
        for future in concurrent.futures.as_completed(futures):
            dns_server = futures[future]
            vulnerabilities = future.result()
            if vulnerabilities:
                logging.info(f"Servidor DNS {dns_server} tiene vulnerabilidades: {', '.join(vulnerabilities)}")
            else:
                logging.info(f"Servidor DNS {dns_server} está seguro de vulnerabilidades DoS.")

# Función principal
def main():
    """Función principal para realizar el análisis DNS."""
    print(f"Sistema operativo: {get_os_info()}")
    print(f"Versión de Python: {get_python_version()}")
    check_authorization()
    get_user_consent()

    url = input("Introduce la URL para analizar los servidores DNS: ")

    analyze_dns(url)

    # Realizar prueba de estrés DNS (opcional)
    dns_servers = get_dns_servers(url)
    for dns_server in dns_servers:
        dns_stress_test(dns_server)

    # Análisis concurrente
    concurrent_dns_analysis(url)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nEjecución interrumpida por el usuario.")
    except Exception as e:
        print(f"Error inesperado: {e}")
