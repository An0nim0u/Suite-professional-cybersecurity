import hashlib
import hmac
import time
from passlib.hash import bcrypt, pbkdf2_sha256, argon2
from Crypto.Hash import MD4, Whirlpool
import tiger
import blake3
import crc32c

# Función para identificar el tipo de hash
def identify_hash_type(hash_string):
    """Identifica el tipo de hash basado en su longitud y formato."""
    hash_types = {
        32: 'MD5',
        40: 'SHA-1',
        56: 'SHA-224',
        64: 'SHA-256',
        96: 'SHA-384',
        128: 'SHA-512',
        64: 'Whirlpool',
        64: 'Blake2',
        128: 'Blake3',
    }

    hash_length = len(hash_string)
    if hash_length in hash_types:
        return hash_types[hash_length]
    
    # Verificar si es un hash SHA-3 o CRC
    if re.match(r'^[0-9a-f]{128}$', hash_string):
        return "SHA-3"
    elif re.match(r'^[0-9a-f]{16}$', hash_string):
        return "CRC32C"
    else:
        return "Desconocido"

# Función para generar hashes de un texto en diferentes algoritmos
def generate_hash(text, algorithm="SHA-256"):
    """Genera un hash del texto dado con el algoritmo especificado."""
    text = text.encode('utf-8')  # Convertir a bytes
    if algorithm == "MD5":
        return hashlib.md5(text).hexdigest()
    elif algorithm == "SHA-1":
        return hashlib.sha1(text).hexdigest()
    elif algorithm == "SHA-256":
        return hashlib.sha256(text).hexdigest()
    elif algorithm == "SHA-512":
        return hashlib.sha512(text).hexdigest()
    elif algorithm == "SHA-224":
        return hashlib.sha224(text).hexdigest()
    elif algorithm == "SHA-384":
        return hashlib.sha384(text).hexdigest()
    elif algorithm == "MD4":
        return MD4.new(text).hexdigest()
    elif algorithm == "Whirlpool":
        return Whirlpool.new(text).hexdigest()
    elif algorithm == "Blake2":
        return blake3.blake2b(text).hexdigest()
    elif algorithm == "Blake3":
        return blake3.blake3(text).hexdigest()
    elif algorithm == "bcrypt":
        return bcrypt.hash(text)
    elif algorithm == "pbkdf2_sha256":
        return pbkdf2_sha256.hash(text)
    elif algorithm == "argon2":
        return argon2.hash(text)
    elif algorithm == "scrypt":
        return hashlib.scrypt(text, salt=b'salt', n=16384, r=8, p=1).hex()
    elif algorithm == "HMAC":
        key = input("Ingresa la clave secreta para HMAC: ").encode('utf-8')
        return hmac.new(key, text, hashlib.sha256).hexdigest()
    elif algorithm == "CRC32C":
        return crc32c.crc32c(text).hex()
    elif algorithm == "SHA-3":
        return hashlib.sha3_256(text).hexdigest()
    else:
        raise ValueError("Algoritmo no soportado")

# Función para sugerir posibles ataques para un hash
def suggest_attack(hash_algorithm):
    """Sugerir posibles ataques en función del tipo de hash."""
    attack_methods = {
        "MD5": "Ataque de diccionario o fuerza bruta.",
        "SHA-1": "Ataque de diccionario o fuerza bruta (SHA-1 ya está obsoleto en muchos casos).",
        "SHA-256": "Ataque de fuerza bruta (requiere mucho tiempo y potencia).",
        "SHA-512": "Ataque de fuerza bruta (muy difícil de romper).",
        "SHA-224": "Ataque de diccionario o fuerza bruta.",
        "SHA-384": "Ataque de fuerza bruta (complejo).",
        "MD4": "Ataque de diccionario o fuerza bruta.",
        "Whirlpool": "Ataque de fuerza bruta (es resistente pero no invulnerable).",
        "Blake2": "Ataque de fuerza bruta (más rápido que SHA).",
        "Blake3": "Ataque de fuerza bruta (rapidez extrema).",
        "bcrypt": "Ataque de diccionario o fuerza bruta con alto coste computacional.",
        "pbkdf2_sha256": "Ataque de diccionario o fuerza bruta con alto coste computacional.",
        "argon2": "Ataque de diccionario o fuerza bruta (recomendado para contraseñas de alta seguridad).",
        "scrypt": "Resistente a ataques de hardware.",
        "HMAC": "Ataques por manipulación de mensajes, si no se maneja adecuadamente.",
        "CRC32C": "No recomendado para criptografía, se utiliza más para integridad de datos.",
        "SHA-3": "Resistente a colisiones, pero susceptible a ataques de fuerza bruta.",
        "Desconocido": "No se puede determinar el tipo de hash. Intenta usar herramientas de descifrado en línea."
    }

    return attack_methods.get(hash_algorithm, "Ataque desconocido o no soportado.")

# Función principal para ejecutar el script
def main():
    print("Bienvenido al Script de Identificación y Generación de Hashes.")
    print("Seleccione una opción:")
    print("1. Identificar un hash existente")
    print("2. Generar un hash de un texto")
    
    option = input("Elige una opción: ")
    
    if option == "1":
        # Identificar hash
        hash_string = input("Ingresa el hash para identificar: ").strip()
        hash_type = identify_hash_type(hash_string)
        print(f"El hash es de tipo: {hash_type}")
        
        if hash_type != "Desconocido":
            print(f"Sugerencia de ataque para {hash_type}: {suggest_attack(hash_type)}")
        else:
            print("No se pudo identificar el hash. Intentando con otras herramientas.")

    elif option == "2":
        # Generar hash
        text = input("Ingresa el texto para generar el hash: ").strip()
        print("Seleccione el algoritmo de hash (MD5, SHA-1, SHA-256, SHA-512, SHA-224, SHA-384, MD4, Whirlpool, Blake2, Blake3, bcrypt, pbkdf2_sha256, argon2, scrypt, HMAC, CRC32C, SHA-3):")
        algorithm = input("Algoritmo: ").strip().lower()

        try:
            generated_hash = generate_hash(text, algorithm)
            print(f"El hash generado ({algorithm}) es: {generated_hash}")
        except ValueError as e:
            print(f"Error: {e}")
        
    else:
        print("Opción no válida. Saliendo...")

if __name__ == "__main__":
    main()
