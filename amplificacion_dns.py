import dns.message
import dns.resolver
import random
import time
import socket
import logging
import concurrent.futures
from datetime import datetime
import json
import os
import platform

# Configuración de logging para obtener un registro detallado
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# Obtiene la información del sistema para registrar en el informe
def get_system_info():
    system_info = {
        "Sistema operativo": platform.system(),
        "Versión": platform.version(),
        "Arquitectura": platform.architecture()[0],
        "Python": platform.python_version(),
    }
    return system_info

# Verificación de entorno autorizado
def verify_environment():
    """Verifica que el script solo se ejecute en entornos autorizados para realizar pruebas de amplificación DNS."""
    allowed_ips = ["192.168.1.100", "192.168.2.200"]  # Aquí deberías agregar las IPs autorizadas para las pruebas
    local_ip = socket.gethostbyname(socket.gethostname())

    if local_ip not in allowed_ips:
        logging.critical("¡Acceso no autorizado! Este script solo puede ejecutarse en entornos autorizados.")
        exit(1)

# Obtener servidores DNS predefinidos
def get_dns_servers():
    """Devuelve una lista de servidores DNS objetivo para realizar amplificación."""
    dns_servers = [
        "8.8.8.8",  # Google DNS
        "8.8.4.4",  # Google DNS
        "1.1.1.1",  # Cloudflare DNS
        "9.9.9.9",  # Quad9 DNS
    ]
    return dns_servers

# Medición del tiempo de latencia para optimizar pruebas
def measure_latency(dns_server):
    """Mide el tiempo de latencia de una consulta a un servidor DNS."""
    start_time = time.time()
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        resolver.resolve("google.com")
        latency = time.time() - start_time
        return latency
    except Exception as e:
        logging.error(f"Error al medir latencia para {dns_server}: {e}")
        return float("inf")

# Realiza una consulta DNS para amplificación
def amplify_dns_query(dns_server, target_domain):
    """Realiza una consulta DNS para simular amplificación."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]

        # Crear una consulta tipo ANY, lo que generará una respuesta más grande
        query = dns.message.make_query(target_domain, dns.rdatatype.ANY)
        
        # Enviar la consulta y obtener la respuesta
        response = resolver.query(query)
        
        # Calcular el factor de amplificación
        query_size = len(query.to_wire())
        response_size = len(response.to_wire())
        amplification_factor = response_size / query_size
        
        return amplification_factor, query_size, response_size
        
    except (dns.resolver.Timeout, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        logging.error(f"Error al hacer la consulta en {dns_server}: {e}")
        return 0, 0, 0

# Realiza múltiples consultas de amplificación
def perform_dns_amplification(dns_servers, target_domain, num_queries=100):
    """Ejecuta el ataque de amplificación DNS masiva."""
    amplification_results = []
    latencies = {}
    
    # Medición de latencia de cada servidor DNS
    for dns_server in dns_servers:
        latency = measure_latency(dns_server)
        latencies[dns_server] = latency
        logging.info(f"Latencia para {dns_server}: {latency:.4f} segundos")
    
    # Ordenar servidores DNS por latencia para priorizar los más rápidos
    dns_servers_sorted = sorted(dns_servers, key=lambda x: latencies[x])

    # Realiza las consultas DNS a los servidores DNS más rápidos primero
    for dns_server in dns_servers_sorted:
        logging.info(f"\nRealizando amplificación DNS en {dns_server}...")
        for _ in range(num_queries):
            amplification_factor, query_size, response_size = amplify_dns_query(dns_server, target_domain)
            if amplification_factor > 0:
                amplification_results.append(amplification_factor)
            time.sleep(0.5)  # Para evitar sobrecargar el servidor con consultas rápidas

    if amplification_results:
        avg_amplification = sum(amplification_results) / len(amplification_results)
        logging.info(f"\nPromedio del factor de amplificación: {avg_amplification:.2f}")
        return avg_amplification, amplification_results
    else:
        logging.warning("No se obtuvieron resultados de amplificación.")
        return 0, []

# Genera un informe detallado de las pruebas realizadas
def generate_report(target_domain, amplification_results, system_info, latencies):
    """Genera un informe detallado sobre el ataque de amplificación DNS realizado."""
    report = {
        "Fecha": str(datetime.now()),
        "Sistema": system_info,
        "Dominio de prueba": target_domain,
        "Latencias DNS (ms)": {dns: latencies[dns] * 1000 for dns in latencies},  # Convertir a milisegundos
        "Amplificación DNS (promedio)": sum(amplification_results) / len(amplification_results) if amplification_results else "N/A",
        "Resultados de amplificación": amplification_results
    }
    
    # Guardar el informe en un archivo JSON
    report_filename = "dns_amplification_report.json"
    with open(report_filename, "w") as f:
        json.dump(report, f, indent=4)
    
    logging.info(f"Informe generado y guardado en {report_filename}")

# Función principal para ejecutar todo el flujo
def simulate_dns_attack():
    """Simula el ataque de amplificación DNS a múltiples servidores."""
    # URL de destino (puedes cambiar esto por el dominio que desees atacar)
    target_domain = "example.com"
    
    # Obtener los servidores DNS predefinidos
    dns_servers = get_dns_servers()

    # Ejecutar la amplificación DNS
    avg_amplification, amplification_results = perform_dns_amplification(dns_servers, target_domain)
    
    # Obtener información del sistema
    system_info = get_system_info()

    # Generar un informe con los resultados
    generate_report(target_domain, amplification_results, system_info, {dns: measure_latency(dns) for dns in dns_servers})

# Verifica que el entorno sea seguro para ejecutar las pruebas
def main():
    try:
        verify_environment()  # Verifica si el entorno es autorizado
        simulate_dns_attack()  # Simula el ataque de amplificación DNS
    except KeyboardInterrupt:
        logging.info("\nSimulación interrumpida por el usuario.")
    except Exception as e:
        logging.error(f"Error inesperado: {e}")

if __name__ == "__main__":
    main()
