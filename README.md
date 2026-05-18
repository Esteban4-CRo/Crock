# CROCK - Pentesting WiFi Tool

**CROCK** es una herramienta avanzada de auditoría y pentesting WiFi diseñada para entornos Linux (Kali, Debian, Ubuntu). Permite el escaneo de redes, captura de handshakes mediante ataques de deautenticación quirúrgicos y cracking secuencial utilizando múltiples diccionarios.

## Características
- **Escaneo en Tiempo Real**: Identificación de APs y clientes con potencia de señal.
- **Ataque de Deautenticación**: Desconexión forzada de clientes para capturar el 4-way handshake.
- **Motor de Cracking Secuencial**: Soporte para múltiples archivos `.txt` en la carpeta `wordlists/`. Si no encuentra la clave en uno, pasa automáticamente al siguiente.


## Requisitos
- Adaptador WiFi con soporte para **Modo Monitor** e **Inyección de Paquetes**.
- Sistema operativo basado en Debian (Kali Linux recomendado).

## Instalación y Configuración
Para preparar el entorno e instalar todas las dependencias necesarias, ejecuta el script de setup:

```bash
chmod +x setup.sh
sudo ./setup.sh
```

El script instalará automáticamente `g++`, `make`, `libpcap`, `openssl`, `aircrack-ng` e `iw`.

## Uso
Una vez configurado, ejecuta la herramienta con privilegios de root:

```bash
sudo ./crock
```

### Gestión de Diccionarios
Coloca tus archivos de contraseñas dentro del directorio `wordlists/`. Desde el panel de **CROCK**, podrás seleccionar cuáles quieres incluir en el ataque.

## Pruebas de Ejecución (Terminal)

```text
 ██████╗██████╗  ██████╗  ██████╗██╗  ██╗
██╔════╝██╔══██╗██╔═══██╗██╔════╝██║ ██╔╝
██║     ██████╔╝██║   ██║██║     █████╔╝ 
██║     ██╔══██╗██║   ██║██║     ██╔═██╗ 
╚██████╗██║  ██║╚██████╔╝╚██████╗██║  ██╗
 ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝
                                         
         PENTESTING WIFI TOOL            
             by EstebanCRO               

[*] Interfaces detectadas:
  [0] wlan0
  [1] eth0
  [2] any

Selecciona interfaz > 
```

## Tutorial

<video src="https://drive.google.com/uc?export=download&id=12wBPDQUab42E2bKibDLSxSbCUUgHYHdP" controls="controls" width="100%">
  Tu navegador no soporta el tag de video. Puedes verlo <a href="https://drive.google.com/file/d/12wBPDQUab42E2bKibDLSxSbCUUgHYHdP/view?usp=sharing">aquí</a>.
</video>

---
**Desarrollado por EstebanCRO**
*Disclaimer: Esta herramienta debe usarse exclusivamente para fines educativos y auditorías autorizadas. El uso en redes ajenas sin permiso es ilegal.*
