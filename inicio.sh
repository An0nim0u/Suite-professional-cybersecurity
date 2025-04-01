#!/bin/bash

# Función para mostrar el menú principal
show_menu() {
  echo "ataque de envenenamiento cache"
  echo "Bienvenido al sistema de pruebas de seguridad."
  echo "Menú Principal:"
  echo "1. Amplificacion dns"
  echo "2. Iniciar ataque Flood"
  echo "3. Escanear puertos"
  echo "4. Analizar vulnerabilidades DoS"
  echo "5. Enumerar servicios DNS"
  echo "6. Analizar vulnerabilidades (Buffer Overflow)"
  echo "7. Salir"
  read -p "Selecciona una opción: " choice
  case $choice in
    1) python3 Cache_Poisoning_Attack.py;;
    2) python3 amplificacion_dns.py ;;
    2) python3 flood_attacks.py ;;
    3) python3 port_scan.py ;;
    4) python3 resolucion.py ;;
    5) python3 dns_analysis.py ;;
    6) python3 buffer_scan.py ;;
    7) echo "Saliendo..."; exit 0 ;;
    *) echo "Opción no válida. Inténtalo de nuevo."; show_menu ;;
  esac
}

# Iniciar el menú principal
show_menu