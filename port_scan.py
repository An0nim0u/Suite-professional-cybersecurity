import socket
import threading
import time
import random
import requests
from urllib.parse import urlparse

# Lista de User-Agents para ataques HTTP
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.2 Safari/605.1.15",
]

def check_slowloris(target_ip, target_port):
    """Verifica la vulnerabilidad Slowloris con mayor precisión."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target_ip, target_port))
        s.send(b"GET /?{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: keep-alive\r\n".format(random.randint(0, 2000), target_ip.encode('utf-8'), random.choice(user_agents).encode('utf-8')))
        time.sleep(15)  # Aumenta el tiempo de espera
        s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode('utf-8'))
        s.close()
        return True
    except (socket.timeout, socket.error):
        return False

def check_rudy(target_ip, target_port):
    """Verifica la vulnerabilidad RUDY con mayor precisión."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target_ip, target_port))
        s.send(b"POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 4294967295\r\nUser-Agent: {}\r\n".format(target_ip.encode('utf-8'), random.choice(user_agents).encode('utf-8')))
        s.send(b"X-Progress-ID: {}\r\n".format(random.randint(1, 5000)))
        return True
    except (socket.timeout, socket.error):
        return False

def check_goldeneye(target_ip, target_port):
    """Verifica la vulnerabilidad GoldenEye con mayor precisión."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target_ip, target_port))
        s.send(b"GET /?{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: keep-alive\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US,en;q=0.5\r\n".format(random.randint(0, 2000), target_ip.encode('utf-8'), random.choice(user_agents).encode('utf-8')))
        return True
    except (socket.timeout, socket.error):
        return False

def check_http_get_flood(target_ip, target_port):
    """Verifica la vulnerabilidad a ataques HTTP GET Flood con mayor precisión."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target_ip, target_port))
        s.send(b"GET /?{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\n\r\n".format(random.randint(0, 2000), target_ip.encode('utf-8'), random.choice(user_agents).encode('utf-8')))
        return True
    except (socket.timeout, socket.error):
        return False

def check_http_post_flood(target_ip, target_port):
    """Verifica la vulnerabilidad a ataques HTTP POST Flood."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target_ip, target_port))
        s.send(b"POST / HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nContent-Length: 10000000\r\n\r\n".format(target_ip.encode('utf-8'), random.choice(user_agents).encode('utf-8')))
        return True
    except (socket.timeout, socket.error):
        return False

def check_slowread(target_ip, target_port):
    """Verifica la vulnerabilidad Slow Read."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target_ip, target_port))
        s.send(b"GET / HTTP/1.1\r\nHost: {}\r\nRange: bytes=0-\r\n\r\n".format(target_ip.encode('utf-8')))
        time.sleep(120)  # Simula una lectura lenta
        s.recv(1024)
        return True
    except (socket.timeout, socket.error):
        return False

def check_syn_flood(target_ip, target_port):
    """Verifica la vulnerabilidad SYN Flood."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target_ip, target_port))
        s.send(b"SYN")
        return True
    except (socket.timeout, socket.error):
        return False

def check_udp_flood(target_ip, target_port):
    """Verifica la vulnerabilidad UDP Flood."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"A" * 1024, (target_ip, target_port))
        return True
    except socket.error:
        return False

def check_icmp_flood(target_ip):
    """Verifica la vulnerabilidad ICMP Flood."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.sendto(b"ICMP_FLOOD", (target_ip, 0))
        return True
    except socket.error:
        return False

def scan_dos_vulnerabilities(target_ip, target_ports):
    """Escanea vulnerabilidades DoS en los puertos especificados con informes detallados."""
    vulnerabilities = {}
    for port in target_ports:
        print(f"Escaneando puerto {port}...")
        results = {}
        results["Slowloris"] = check_slowloris(target_ip, port)
        results["RUDY"] = check_rudy(target_ip, port)
        results["GoldenEye"] = check_goldeneye(target_ip, port)
        results["HTTP GET Flood"] = check_http_get_flood(target_ip, port)
        results["HTTP POST Flood"] = check_http_post_flood(target_ip, port)
        results["Slow Read"] = check_slowread(target_ip, port)
        results["SYN Flood"] = check_syn_flood(target_ip, port)
        results["UDP Flood"] = check_udp_flood(target_ip, port)
        if port == 0:
            results["ICMP Flood"] = check_icmp_flood(target_ip)
        for vuln, detected in results.items():
            if detected:
                vulnerabilities[port] = vulnerabilities.get(port, []) + [vuln]
    return vulnerabilities

def generate_report(vulnerabilities):
    """Genera un informe detallado de las vulnerabilidades encontradas."""
    if vulnerabilities:
        print("\nInforme de vulnerabilidades DoS:")
        for port, vuln_list in vulnerabilities.items():
            print(f"Puerto {port}: Vulnerable a {', '.join(vuln_list)}")
    else:
        print("\nNo se encontraron vulnerabilidades DoS.")

def scan_ports(target_ip, port_range):
    """Escanea puertos abiertos y vulnerabilidades DoS."""
    open_ports = []
    print(f"Escaneando puertos en {target_ip}...")
    for port in port_range:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"Puerto abierto detectado: {port}")
        except socket.error:
            pass
    if open_ports:
        print(f"Puertos abiertos encontrados: {', '.join(map(str, open_ports))}")
        vulnerabilities = scan_dos_vulnerabilities(target_ip, open_ports)
        generate_report(vulnerabilities)
    else:
        print("No se encontraron puertos abiertos.")

if __name__ == "__main__":
    target_ip = input("Introduce la IP de destino: ")
    port_range = range(1, 65535)
    scan_ports(target_ip, port_range)