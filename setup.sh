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
