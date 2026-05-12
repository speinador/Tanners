# ⬡ TANNERS
### Security Reconnaissance & Vulnerability Assessment Tool

```
  ████████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ ███████╗
  ╚══██╔══╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗██╔════╝
     ██║   ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝███████╗
     ██║   ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗╚════██║
     ██║   ██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║███████║
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝
```

> ⚠️ **Solo para uso en sistemas con autorización explícita.**  
> El uso no autorizado de esta herramienta puede ser ilegal. El autor no se responsabiliza por el uso indebido.

---

## ¿Qué es TANNERS?

TANNERS es una herramienta de reconocimiento y análisis de vulnerabilidades en redes, escrita en Python 3. Automatiza múltiples fases de un pentest o auditoría de seguridad: desde la recolección de información pasiva (WHOIS, DNS) hasta el escaneo activo de puertos y servicios, análisis web, SMB, FTP, SSH y MySQL.

Al finalizar, genera un **dashboard HTML interactivo** con todos los hallazgos clasificados según el estándar **CVSS v3**, listo para compartir como reporte.

---

## Características

- 🔍 **Reconocimiento pasivo** — WHOIS, registros DNS (A, MX, NS, TXT, AAAA), NSLookup
- 🔌 **Escaneo de puertos** — nmap con detección de versiones y scripts NSE
- 🌐 **Análisis web** — Nikto, WhatWeb, Gobuster / Dirb
- 🗂 **Análisis SMB** — Enum4Linux, scripts NSE de vulnerabilidades SMB (MS17-010, EternalBlue, etc.)
- 📁 **Análisis FTP** — detección de login anónimo y vulnerabilidades
- 🔐 **Análisis SSH** — ssh-audit o scripts NSE como fallback
- 🗄 **Análisis MySQL** — sqlmap, detección de root sin contraseña
- 📊 **Scoring CVSS automático** — 25+ reglas de detección con score, vector y severidad
- 🗺 **Multi-target / CIDR** — escanea IPs individuales, rangos CIDR y listas desde archivo
- 📄 **Dashboard HTML interactivo** — reporte con tabs, filtros, barras de severidad y salida por herramienta
- 🛡 **Validación de targets** — protección contra inyección de comandos shell

---

## Requisitos

### Python
- Python 3.8 o superior
- Solo usa la biblioteca estándar (no requiere `pip install`)

### Herramientas del sistema

TANNERS orquesta herramientas externas. Las **requeridas** son esenciales para el funcionamiento básico; las **opcionales** amplían la cobertura.

| Herramienta | Tipo | Función |
|---|---|---|
| `nmap` | Requerida | Escaneo de puertos y scripts NSE |
| `whois` | Requerida | Reconocimiento pasivo |
| `dig` | Requerida | Consultas DNS |
| `nslookup` | Requerida | Resolución de nombres |
| `nikto` | Opcional | Análisis de vulnerabilidades web |
| `whatweb` | Opcional | Fingerprinting de tecnologías web |
| `gobuster` | Opcional | Fuerza bruta de directorios |
| `dirb` | Opcional | Alternativa a gobuster |
| `enum4linux` | Opcional | Enumeración SMB |
| `ssh-audit` | Opcional | Auditoría de configuración SSH |
| `sqlmap` | Opcional | Detección de SQL Injection |

**Instalar todas en Debian/Ubuntu/Kali:**
```bash
sudo apt update
sudo apt install nmap whois dnsutils nikto whatweb gobuster dirb enum4linux ssh-audit sqlmap
```

---

## Instalación

```bash
git clone https://github.com/tu-usuario/tanners.git
cd tanners
chmod +x tanners.py
```

No se necesita ningún entorno virtual ni dependencia de pip.

---

## Uso

### Sintaxis general

```bash
python3 tanners.py [targets...] [opciones]
```

### Ejemplos

```bash
# Escanear un dominio
python3 tanners.py example.com

# Escanear una IP
python3 tanners.py 192.168.1.10

# Escanear un rango CIDR completo
python3 tanners.py 192.168.1.0/24

# Múltiples targets a la vez
python3 tanners.py 10.0.0.1 10.0.0.2 10.0.0.5

# Targets desde un archivo (uno por línea, # para comentarios)
python3 tanners.py targets.txt

# Especificar nombre del reporte HTML de salida
python3 tanners.py example.com -o reporte_ejemplo.html

# Solo verificar que las herramientas estén instaladas
python3 tanners.py --check-only

# Omitir reconocimiento pasivo (más rápido)
python3 tanners.py example.com --skip-passive

# Solo escaneo de puertos, sin análisis de servicios
python3 tanners.py example.com --ports-only
```

### Archivo de targets

Se puede pasar un archivo `.txt` con un target por línea. Las líneas que comienzan con `#` son ignoradas:

```
# Servidores de producción
192.168.1.10
192.168.1.11
example.com

# Red interna
10.0.0.0/24
```

---

## Opciones

| Opción | Descripción |
|---|---|
| `-o`, `--output` | Ruta del dashboard HTML generado (default: `tanners_YYYYMMDD_HHMMSS.html`) |
| `--check-only` | Solo verifica dependencias instaladas y termina |
| `--skip-passive` | Omite WHOIS, DNS y NSLookup |
| `--ports-only` | Solo ejecuta nmap, sin análisis de servicios web/SMB/SSH/etc. |

---

## Fases de ejecución

```
Fase 1 · Reconocimiento pasivo
        WHOIS → Registros DNS (A/MX/NS/TXT/AAAA) → NSLookup

Fase 2 · Escaneo de puertos
        nmap -sV -sC en puertos comunes

Fase 3A · Análisis web        (si hay puertos 80/443/8080/8443)
        Nikto → WhatWeb → Gobuster / Dirb

Fase 3B · Análisis SMB        (si el puerto 445 está abierto)
        Enum4Linux → Nmap SMB scripts

Fase 3C · Análisis FTP        (si el puerto 21 está abierto)
        Nmap FTP scripts (anon login, brute, vulns)

Fase 3D · Análisis SSH        (si el puerto 22 está abierto)
        ssh-audit (o Nmap SSH scripts como fallback)

Fase 3E · Análisis MySQL      (si el puerto 3306 está abierto)
        SQLMap → Nmap MySQL scripts

Fase 4 · Nikto extendido      (si hay puertos web)
        Nikto con todos los tunnings activos
```

---

## Dashboard HTML

Al finalizar, TANNERS genera un archivo `.html` autocontenido que se puede abrir en cualquier navegador sin servidor web.

El reporte incluye:

- **Resumen ejecutivo** con contadores por severidad (Crítico / Alto / Medio / Bajo / Info)
- **Barras de proporción** animadas por nivel de severidad
- **Pestaña de hallazgos CVSS** — tabla filtrable con todos los findings, score, vector y evidencia
- **Pestaña de detalle por target** — puertos abiertos, registros DNS y salida completa de cada herramienta (expandible)

---

## Scoring CVSS

TANNERS analiza la salida de cada herramienta con más de 25 reglas de expresiones regulares mapeadas a scores CVSS v3 y vectores estándar. Algunos ejemplos:

| Detección | Score CVSS | Severidad |
|---|---|---|
| EternalBlue / MS17-010 | 9.8 | Crítico |
| FTP anonymous login | 9.1 | Crítico |
| MySQL root sin contraseña | 9.4 | Crítico |
| Redis sin autenticación | 9.8 | Crítico |
| CVE genérico detectado | 7.5 | Alto |
| SQL Injection | 8.6 | Alto |
| SSL/TLS inseguro (SSLv2, Heartbleed...) | 7.4 | Alto |
| Directory listing expuesto | 5.3 | Medio |
| Falta cabecera HSTS | 4.8 | Medio |
| Banner de servidor expuesto | 3.7 | Bajo |

> Los hallazgos son orientativos. Siempre verificar manualmente. Las herramientas automáticas pueden generar falsos positivos.

---

## Seguridad del propio script

- Los targets son validados con una expresión regular antes de usarse en cualquier comando. Strings que contengan caracteres de shell (`;`, `|`, `$`, backticks, etc.) son rechazados.
- `tool_exists()` usa `shutil.which()` en lugar de ejecutar un subshell.
- La recursión en archivos de targets está protegida contra referencias circulares.

---

## Estructura del proyecto

```
tanners/
├── tanners.py       # Script principal
└── README.md        # Este archivo
```

---

## Limitaciones conocidas

- Diseñado para Linux (Kali, Ubuntu, Debian). No probado en macOS ni Windows.
- Los tiempos de escaneo en redes /24 pueden ser considerables (varios minutos por host).
- sqlmap apunta a `http://{target}/` para detección básica; para inyección en endpoints específicos se recomienda usarlo directamente.
- Los timeouts de nmap (600s por target) son conservadores; en redes grandes se recomienda `--ports-only` para un primer barrido rápido.

---

## Contribuir

Pull requests bienvenidos. Algunas ideas para mejorar:

- [ ] Soporte para exportar el reporte en JSON
- [ ] Integración con Shodan API para reconocimiento pasivo extendido
- [ ] Detección de WAF antes del análisis web
- [ ] Soporte para IPv6 en todas las fases
- [ ] Modo silencioso (`--quiet`) sin output en consola

---

## Licencia

MIT License. Libre para usar, modificar y distribuir con atribución.

---

## Disclaimer

Esta herramienta fue desarrollada con fines educativos y de auditoría legítima. El uso en sistemas sin autorización explícita del propietario puede ser ilegal bajo las leyes de tu país. El autor no se hace responsable del uso indebido.
