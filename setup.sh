#!/bin/bash

# CROCK - Pentesting WiFi Tool Setup
# by EstebanCRO

echo "[*] Iniciando configuración de CROCK..."

# Detectar OS
if [ -f /etc/debian_version ]; then
    echo "[*] Sistema basado en Debian detectado."
    sudo apt-get update
    sudo apt-get install -y g++ make libpcap-dev libssl-dev aircrack-ng wireless-tools iw
else
    echo "[!] Este script está diseñado para Debian/Kali/Ubuntu."
    echo "[!] Por favor, instala manualmente: g++, make, libpcap, openssl, aircrack-ng, iw."
fi

# Crear directorio de wordlists si no existe
mkdir -p wordlists

echo "[*] Descargando diccionarios para hacer la herramienta imparable..."
# 1. Rockyou (clásico e indispensable)
if [ ! -f wordlists/rockyou.txt ]; then
    echo "  -> Descargando rockyou.txt (134 MB)..."
    wget -q --show-progress https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O wordlists/rockyou.txt
fi

# 2. Top 1 Millón de passwords (SecLists)
if [ ! -f wordlists/top_1M.txt ]; then
    echo "  -> Descargando Top 1 Millón (SecLists)..."
    wget -q --show-progress https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt -O wordlists/top_1M.txt
fi

# 3. Credenciales por defecto de Routers
if [ ! -f wordlists/router_defaults.txt ]; then
    echo "  -> Descargando contraseñas por defecto de routers..."
    wget -q --show-progress https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/default-passwords.txt -O wordlists/router_defaults.txt
fi
echo "[+] Diccionarios descargados y listos en la carpeta wordlists/."

# Compilar el proyecto
echo "[*] Compilando CROCK..."
make clean
make

if [ $? -eq 0 ]; then
    echo "[+] CROCK compilado con éxito."
    echo "[+] Uso: sudo ./crock"
else
    echo "[-] Error en la compilación."
    exit 1
fi
