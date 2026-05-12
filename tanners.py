#!/usr/bin/env python3
"""
TANNERS v2.1 — Security Reconnaissance & Vulnerability Assessment Tool
Fixes aplicados:
  - Validación de targets antes de ejecutar comandos shell (anti-inyección)
  - tool_exists() usa shutil.which() en lugar de shell=True
  - sqlmap invocado correctamente con URL http://
  - Bug de lógica sbars corregido ("".join([str]) → str directo)
  - expand_targets() protegido contra recursión circular (archivos)
  - Salida de sqlmap truncada en Python, no con pipe en shell
"""

import subprocess, sys, re, json, argparse, ipaddress, html, shutil
from datetime import datetime
from pathlib import Path


# ══════════════════════════════════════════════════════════════════
#  COLORES ANSI
# ══════════════════════════════════════════════════════════════════
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


# ══════════════════════════════════════════════════════════════════
#  BANNER ASCII ART  (mejorado)
# ══════════════════════════════════════════════════════════════════
def banner():
    art = [
        r"  ████████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ ███████╗",
        r"  ╚══██╔══╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗██╔════╝",
        r"     ██║   ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝███████╗",
        r"     ██║   ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗╚════██║",
        r"     ██║   ██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║███████║",
        r"     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝",
    ]
    grad = [C.CYAN, C.CYAN, C.BLUE, C.BLUE, C.MAGENTA, C.MAGENTA]

    W = 66  # ancho del marco

    print()
    print(f"  {C.DIM}╔{'═' * W}╗{C.RESET}")
    for i, line in enumerate(art):
        # centrar cada línea dentro del marco
        inner = line.strip()
        pad_total = W - len(inner)
        lp = pad_total // 2
        rp = pad_total - lp
        print(f"  {C.DIM}║{C.RESET}{' ' * lp}"
              f"{grad[i]}{C.BOLD}{inner}{C.RESET}"
              f"{' ' * rp}{C.DIM}║{C.RESET}")
    print(f"  {C.DIM}╠{'═' * W}╣{C.RESET}")

    subtitle = "Security Reconnaissance & Vulnerability Assessment Tool"
    version  = "v2.1"
    warning  = "⚠  Solo para uso en sistemas con autorización explícita"

    for line in [subtitle + "  " + C.DIM + version + C.RESET + C.WHITE, warning]:
        clean = re.sub(r'\033\[[0-9;]*m', '', line)   # medir sin ANSI
        pad_total = W - len(clean)
        lp = pad_total // 2
        rp = pad_total - lp
        if "⚠" in line:
            print(f"  {C.DIM}║{C.RESET}{' ' * lp}"
                  f"{C.YELLOW}{line}{C.RESET}"
                  f"{' ' * rp}{C.DIM}║{C.RESET}")
        else:
            print(f"  {C.DIM}║{C.RESET}{' ' * lp}"
                  f"{C.WHITE}{line}{C.RESET}"
                  f"{' ' * rp}{C.DIM}║{C.RESET}")

    print(f"  {C.DIM}╚{'═' * W}╝{C.RESET}")
    print()


# ══════════════════════════════════════════════════════════════════
#  HELPERS DE CONSOLA
# ══════════════════════════════════════════════════════════════════
def hdr(title):
    w = 64
    print(f"\n{C.BLUE}{C.BOLD}╔{'═' * w}╗")
    pad = max(0, w - len(title) - 2)
    print(f"║  {title}{' ' * pad}║")
    print(f"╚{'═' * w}╝{C.RESET}")

def ok(msg):   print(f"  {C.GREEN}✔{C.RESET}  {msg}")
def warn(msg): print(f"  {C.YELLOW}⚠{C.RESET}  {msg}")
def err(msg):  print(f"  {C.RED}✘{C.RESET}  {msg}")
def info(msg): print(f"  {C.CYAN}›{C.RESET}  {msg}")
def step(msg): print(f"\n  {C.MAGENTA}◈{C.RESET}  {C.BOLD}{msg}{C.RESET}")


# ══════════════════════════════════════════════════════════════════
#  UTILIDADES
# ══════════════════════════════════════════════════════════════════

# ── FIX: tool_exists usa shutil.which (sin shell) ────────────────
def tool_exists(name: str) -> bool:
    """Detecta si un ejecutable está en PATH sin lanzar un subshell."""
    return shutil.which(name) is not None


# ── FIX: validación de targets para evitar inyección de comandos ─
_SAFE_TARGET_RE = re.compile(
    r'^('
    r'(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?'   # IPv4 / CIDR
    r'|([0-9a-fA-F:]+/\d{1,3})'            # IPv6 / CIDR
    r'|([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*)'  # dominio
    r')$'
)

def validate_target(target: str) -> bool:
    """Devuelve True si el target es una IP, CIDR o dominio válido."""
    return bool(_SAFE_TARGET_RE.match(target.strip()))


def run_cmd(cmd: str, timeout: int = 300):
    """Ejecuta un comando shell y devuelve (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout
        )
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"[TIMEOUT] Superó {timeout}s", 1
    except Exception as e:
        return "", str(e), 1


def check_tools(tools):
    missing = []
    for t in tools:
        if tool_exists(t):
            ok(t)
        else:
            warn(f"{t} → NO instalado")
            missing.append(t)
    return missing


# ── FIX: expand_targets protegido contra recursión circular ──────
def expand_targets(raw: str, _visited: set = None) -> list:
    """Acepta IP, dominio, CIDR o archivo con targets."""
    if _visited is None:
        _visited = set()

    targets = []
    p = Path(raw)

    # ── Archivo de targets ────────────────────────────────────────
    if p.exists() and p.is_file():
        resolved = str(p.resolve())
        if resolved in _visited:
            warn(f"Referencia circular ignorada: {raw}")
            return []
        _visited.add(resolved)
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets += expand_targets(line, _visited)
        return targets

    # ── CIDR / IP ────────────────────────────────────────────────
    try:
        net   = ipaddress.ip_network(raw, strict=False)
        hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
        return [str(h) for h in hosts]
    except ValueError:
        pass

    # ── Dominio u otro string ────────────────────────────────────
    return [raw]


# ══════════════════════════════════════════════════════════════════
#  SCORING CVSS
# ══════════════════════════════════════════════════════════════════
CVSS_RULES = [
    (r"VULNERABLE|vuln FOUND|CVE-\d{4}-\d+.*CRITICAL",
     "Vulnerabilidad crítica confirmada", 9.8,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    (r"Anonymous FTP login|ftp-anon.*allowed",
     "FTP permite login anónimo", 9.1,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    (r"MS17-010|EternalBlue|WannaCry",
     "Posible EternalBlue (MS17-010)", 9.8,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    (r"mysql.*empty.password|mysql-empty-password.*root",
     "MySQL root sin contraseña", 9.4,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    (r"redis.*without.*password|redis.*unauthenticated",
     "Redis expuesto sin autenticación", 9.8,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    (r"CVE-\d{4}-\d+",
     "CVE detectado", 7.5,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (r"SSLv2|SSLv3|POODLE|BEAST|Heartbleed|RC4",
     "Protocolo SSL/TLS inseguro", 7.4,
     "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    (r"Default credential|default password|admin:admin|test:test",
     "Credenciales por defecto encontradas", 8.8,
     "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    (r"smb-vuln|ms08-067|ms06-025",
     "Vulnerabilidad SMB detectada", 8.1,
     "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    (r"SQL injection|sqlmap.*injectable|Parameter.*injectable",
     "Posible SQL Injection", 8.6,
     "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    (r"php/[0-4]\.|apache/[01]\.|nginx/[01]\.",
     "Versión de servidor web muy antigua", 7.5,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (r"OpenSSH [1-6]\.",
     "Versión OpenSSH desactualizada", 7.2,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (r"X-Frame-Options.*missing|Clickjacking",
     "Falta cabecera X-Frame-Options", 4.3,
     "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    (r"X-Content-Type.*missing|MIME sniffing",
     "Falta X-Content-Type-Options", 4.3,
     "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    (r"Strict-Transport-Security.*missing|HSTS.*not set",
     "Falta HSTS", 4.8,
     "AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    (r"Content-Security-Policy.*missing|CSP.*not",
     "Falta Content-Security-Policy", 4.7,
     "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    (r"Directory.*listing|DIRECTORY LISTING|Index of /",
     "Directory listing expuesto", 5.3,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    (r"PHPSESSID|session.*cookie.*secure.*false|HttpOnly.*false",
     "Cookie de sesión insegura", 5.4,
     "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    (r"robots\.txt.*Disallow|\.git|\.env|\.bak|\.sql",
     "Archivo/ruta sensible expuesto", 5.3,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    (r"telnet|port 23.*open",
     "Telnet abierto (protocolo inseguro)", 6.5,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    (r"weak.*cipher|NULL cipher|export cipher",
     "Cipher débil en uso", 5.9,
     "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (r"smtp.*open relay|VRFY.*allowed|EXPN.*allowed",
     "SMTP relay o enumeración habilitada", 5.8,
     "AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N"),
    (r"Server:.*Apache|Server:.*nginx|Server:.*IIS|X-Powered-By",
     "Banner de servidor expuesto", 3.7,
     "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    (r"WordPress|Drupal|Joomla",
     "CMS detectado (verificar versión)", 3.1,
     "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    (r"Traceroute|traceroute hop",
     "Traceroute activo (info leakage)", 2.6,
     "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
]

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_LABEL = {
    "Critical": ("#e63946", "CRÍTICO"),
    "High":     ("#f4793b", "ALTO"),
    "Medium":   ("#f4d03f", "MEDIO"),
    "Low":      ("#4caf50", "BAJO"),
    "Info":     ("#64b5f6", "INFO"),
}


def cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    if score >= 0.1: return "Low"
    return "Info"


def score_output(text: str, source: str, target_id: str) -> list:
    findings, seen = [], set()
    COL = {"Critical": C.RED, "High": C.YELLOW,
           "Medium": C.CYAN, "Low": C.GREEN, "Info": C.BLUE}
    for pattern, desc, score, vector in CVSS_RULES:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches and desc not in seen:
            seen.add(desc)
            ev = matches[0] if isinstance(matches[0], str) else " | ".join(matches[0])
            sev = cvss_to_severity(score)
            findings.append({
                "target":   target_id,
                "source":   source,
                "desc":     desc,
                "score":    score,
                "vector":   vector,
                "severity": sev,
                "evidence": str(ev)[:200],
            })
            lbl = SEVERITY_LABEL[sev][1]
            print(f"    {COL[sev]}[{lbl}]{C.RESET} {desc} (CVSS {score:.1f})")
    return findings


# ══════════════════════════════════════════════════════════════════
#  FASES DE ESCANEO
# ══════════════════════════════════════════════════════════════════
def phase_passive(target: str, results: dict):
    hdr(f"FASE 1 · RECONOCIMIENTO PASIVO — {target}")
    results["passive"] = {}

    info("WHOIS...")
    out, er, _ = run_cmd(f"whois {target}", timeout=30)
    results["passive"]["whois"] = out or er or "Sin datos"
    ok("WHOIS completado") if out else warn("WHOIS sin resultados")

    info("Registros DNS (dig)...")
    dig = {}
    for rtype in ["A", "MX", "NS", "TXT", "AAAA"]:
        out, _, _ = run_cmd(f"dig {rtype} {target} +short", timeout=20)
        dig[rtype] = out.strip() or "—"
        if out.strip():
            ok(f"DNS {rtype}: {out.strip()[:80]}")
    results["passive"]["dig"] = dig

    info("NSLookup...")
    out, er, _ = run_cmd(f"nslookup {target}", timeout=20)
    results["passive"]["nslookup"] = out or er or "Sin datos"
    ok("nslookup completado") if out else warn("nslookup sin datos")


def phase_nmap(target: str, results: dict) -> list:
    hdr(f"FASE 2 · ESCANEO DE PUERTOS — {target}")
    info("Ejecutando nmap (puede tardar varios minutos)...")
    ports = ("21,22,23,25,53,80,110,135,139,143,389,443,445,"
             "636,1433,3306,3389,5432,6379,8080,8443,27017")
    out, er, _ = run_cmd(
        f"nmap -sV -sC -T4 --open -p {ports} {target}", timeout=600)
    open_ports = []
    for line in (out or "").splitlines():
        m = re.match(r"^(\d+)/tcp\s+open\s+(.+)$", line.strip())
        if m:
            port, service = int(m.group(1)), m.group(2).strip()
            open_ports.append({"port": port, "service": service})
            ok(f"Puerto {port}/tcp → {service}")
    results["nmap"] = {"raw": out or er, "open_ports": open_ports}
    results.setdefault("findings", []).extend(
        score_output(out or "", "nmap", target))
    if not open_ports:
        warn("No se detectaron puertos abiertos")
    return [p["port"] for p in open_ports]


def phase_web(target: str, open_ports: list, results: dict):
    web_ports = [p for p in open_ports if p in (80, 443, 8080, 8443)]
    if not web_ports:
        return
    hdr(f"FASE 3A · ANÁLISIS WEB — {target}")
    results["web"] = {}
    proto  = "https" if (443 in open_ports or 8443 in open_ports) else "http"
    port_s = f":{web_ports[0]}" if web_ports[0] not in (80, 443) else ""
    url    = f"{proto}://{target}{port_s}"

    for tool, cmd_t in [
        ("nikto",   f"nikto -h {url} -maxtime 120"),
        ("whatweb", f"whatweb -a 3 {url}"),
    ]:
        if tool_exists(tool):
            step(f"{tool.upper()} → {url}")
            out, er, _ = run_cmd(cmd_t, timeout=180)
            results["web"][tool] = out or er or "Sin resultados"
            results.setdefault("findings", []).extend(
                score_output(results["web"][tool], tool, target))
            ok(f"{tool} completado")
        else:
            warn(f"{tool} no instalado")
            results["web"][tool] = "Herramienta no instalada"

    if tool_exists("gobuster"):
        step(f"GOBUSTER → {url}")
        wl = next((w for w in [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
        ] if Path(w).exists()), None)
        if wl:
            out, er, _ = run_cmd(
                f"gobuster dir -u {url} -w {wl} -t 20 --timeout 10s -q",
                timeout=300)
            results["web"]["dirbuster"] = out or er or "Sin resultados"
            results.setdefault("findings", []).extend(
                score_output(results["web"]["dirbuster"], "gobuster", target))
            ok("Gobuster completado")
        else:
            results["web"]["dirbuster"] = "Wordlist no encontrada"
    elif tool_exists("dirb"):
        step(f"DIRB → {url}")
        out, er, _ = run_cmd(f"dirb {url} -r -S", timeout=300)
        results["web"]["dirbuster"] = out or er or "Sin resultados"
        results.setdefault("findings", []).extend(
            score_output(results["web"]["dirbuster"], "dirb", target))
        ok("Dirb completado")
    else:
        results["web"]["dirbuster"] = "gobuster/dirb no instalados"


def phase_smb(target: str, open_ports: list, results: dict):
    if 445 not in open_ports:
        return
    hdr(f"FASE 3B · ANÁLISIS SMB (445) — {target}")
    results["smb"] = {}
    if tool_exists("enum4linux"):
        step("ENUM4LINUX")
        out, er, _ = run_cmd(f"enum4linux -a {target}", timeout=300)
        results["smb"]["enum4linux"] = out or er or "Sin resultados"
        results.setdefault("findings", []).extend(
            score_output(results["smb"]["enum4linux"], "enum4linux", target))
        ok("Enum4Linux completado")
    else:
        warn("enum4linux no instalado")
        results["smb"]["enum4linux"] = "No instalado"

    step("NMAP SMB scripts")
    out, er, _ = run_cmd(
        f"nmap --script smb-vuln*,smb-enum-shares,smb-enum-users -p 445 {target}",
        timeout=120)
    results["smb"]["nmap_smb"] = out or er or "Sin resultados"
    results.setdefault("findings", []).extend(
        score_output(results["smb"]["nmap_smb"], "nmap-smb", target))
    ok("Nmap SMB completado")


def phase_ftp(target: str, open_ports: list, results: dict):
    if 21 not in open_ports:
        return
    hdr(f"FASE 3C · ANÁLISIS FTP (21) — {target}")
    step("NMAP FTP scripts")
    out, er, _ = run_cmd(
        f"nmap --script ftp-vuln*,ftp-anon,ftp-brute -p 21 {target}",
        timeout=180)
    results["ftp"] = {"nmap_ftp": out or er or "Sin resultados"}
    results.setdefault("findings", []).extend(
        score_output(results["ftp"]["nmap_ftp"], "nmap-ftp", target))
    ok("FTP scripts completados")


def phase_ssh(target: str, open_ports: list, results: dict):
    if 22 not in open_ports:
        return
    hdr(f"FASE 3D · ANÁLISIS SSH (22) — {target}")
    results["ssh"] = {}
    if tool_exists("ssh-audit"):
        step("SSH-AUDIT")
        out, er, _ = run_cmd(f"ssh-audit {target}", timeout=60)
        results["ssh"]["ssh_audit"] = out or er or "Sin resultados"
        results.setdefault("findings", []).extend(
            score_output(results["ssh"]["ssh_audit"], "ssh-audit", target))
        ok("SSH-Audit completado")
    else:
        step("NMAP SSH scripts (fallback)")
        out, er, _ = run_cmd(
            f"nmap --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey -p 22 {target}",
            timeout=120)
        results["ssh"]["nmap_ssh"] = out or er or "Sin resultados"
        results.setdefault("findings", []).extend(
            score_output(results["ssh"]["nmap_ssh"], "nmap-ssh", target))
        ok("Nmap SSH scripts completados")


def phase_mysql(target: str, open_ports: list, results: dict):
    if 3306 not in open_ports:
        return
    hdr(f"FASE 3E · ANÁLISIS MySQL (3306) — {target}")
    results["mysql"] = {}

    # ── FIX: sqlmap necesita una URL http:// válida, no host:puerto ──
    # ── FIX: salida truncada en Python, no con pipe en shell ─────────
    if tool_exists("sqlmap"):
        step("SQLMAP")
        url_mysql = f"http://{target}/"
        out, er, _ = run_cmd(
            f"sqlmap -u {url_mysql} --batch --level=1 --risk=1 --timeout=10",
            timeout=120)
        # Truncar en Python (sin depender de 'head' en el shell)
        lines = (out or er or "Sin resultados").splitlines()
        results["mysql"]["sqlmap"] = "\n".join(lines[:60])
        results.setdefault("findings", []).extend(
            score_output(results["mysql"]["sqlmap"], "sqlmap", target))
        ok("SQLMap completado")
    else:
        results["mysql"]["sqlmap"] = "sqlmap no instalado"

    step("NMAP MySQL scripts")
    out, er, _ = run_cmd(
        f"nmap --script mysql-vuln*,mysql-info,mysql-empty-password -p 3306 {target}",
        timeout=120)
    results["mysql"]["nmap_mysql"] = out or er or "Sin resultados"
    results.setdefault("findings", []).extend(
        score_output(results["mysql"]["nmap_mysql"], "nmap-mysql", target))
    ok("Nmap MySQL completado")


def phase_nikto_extra(target: str, open_ports: list, results: dict):
    if not any(p in open_ports for p in (80, 443, 8080, 8443)):
        return
    hdr(f"FASE 4 · NIKTO EXTENDIDO — {target}")
    if not tool_exists("nikto"):
        results["nikto_extra"] = "nikto no instalado"
        return
    proto = "https" if (443 in open_ports or 8443 in open_ports) else "http"
    url   = f"{proto}://{target}"
    step(f"Nikto full-tuning → {url}")
    out, er, _ = run_cmd(
        f"nikto -h {url} -Format txt -maxtime 300 -Tuning 1234567890abc",
        timeout=400)
    results["nikto_extra"] = out or er or "Sin resultados"
    results.setdefault("findings", []).extend(
        score_output(results["nikto_extra"], "nikto-ext", target))
    ok("Nikto extendido completado")


# ══════════════════════════════════════════════════════════════════
#  HTML DASHBOARD
# ══════════════════════════════════════════════════════════════════
SEV_COLOR = {
    "Critical": "#e63946",
    "High":     "#f4793b",
    "Medium":   "#f4d03f",
    "Low":      "#4caf50",
    "Info":     "#64b5f6",
}


def sev_badge(sev: str) -> str:
    col = SEV_COLOR.get(sev, "#aaa")
    lbl = SEVERITY_LABEL.get(sev, (None, sev))[1]
    tc  = "#111" if sev == "Medium" else "#fff"
    return f'<span class="badge" style="background:{col};color:{tc}">{lbl}</span>'


def esc(t) -> str:
    return html.escape(str(t))


def code_block(title: str, content: str, uid: str) -> str:
    c = esc(content or "Sin datos")
    return (f'<div class="card" id="{uid}">'
            f'<div class="card-hdr" onclick="tog(\'{uid}\')">'
            f'<span>{title}</span><span class="chev">▾</span></div>'
            f'<div class="card-body"><pre>{c}</pre></div></div>')


def generate_html(all_results: dict, output_path: str) -> bool:
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    targets  = list(all_results.keys())
    all_findings = []
    for r in all_results.values():
        all_findings.extend(r.get("findings", []))
    counts   = {s: sum(1 for f in all_findings if f["severity"] == s)
                for s in SEV_ORDER}
    total    = len(all_findings)
    sorted_f = sorted(all_findings, key=lambda f: SEV_ORDER.index(f["severity"]))

    # ── score bars ──────────────────────────────────────────────
    sbars = ""
    for sev in SEV_ORDER:
        cnt = counts[sev]
        if not cnt:
            continue
        pct  = cnt / max(total, 1) * 100
        lbl  = SEVERITY_LABEL[sev][1]
        sbars += (f'<div class="sbr"><span class="slbl">{lbl}</span>'
                  f'<div class="strk"><div class="sfil" '
                  f'style="width:{pct:.1f}%;background:{SEV_COLOR[sev]}"></div></div>'
                  f'<span class="scnt">{cnt}</span></div>')

    # ── findings rows (pestaña global) ──────────────────────────
    grow = ""
    for f in sorted_f:
        grow += (f'<tr><td><code>{esc(f["target"])}</code></td>'
                 f'<td>{sev_badge(f["severity"])}</td>'
                 f'<td class="sc">{f["score"]:.1f}</td>'
                 f'<td>{esc(f["desc"])}</td>'
                 f'<td><code>{esc(f["source"])}</code></td>'
                 f'<td><code class="vec">{esc(f["vector"])}</code></td>'
                 f'<td class="ev">{esc(f["evidence"])}</td></tr>')

    # ── secciones por target ─────────────────────────────────────
    tsecs = ""
    for idx, (target, res) in enumerate(all_results.items()):
        tid      = f"t{idx}"
        dig      = res.get("passive", {}).get("dig", {})
        dns_rows = "".join(
            f"<tr><td><b>{k}</b></td><td>{esc(v)}</td></tr>"
            for k, v in dig.items()
        )
        op = res.get("nmap", {}).get("open_ports", [])
        pr = ("".join(
            f"<tr><td><code>{p['port']}/tcp</code></td><td>{esc(p['service'])}</td></tr>"
            for p in op
        ) or "<tr><td colspan='2'>Sin puertos abiertos</td></tr>")

        tf   = [f for f in all_findings if f["target"] == target]
        tr2  = ""
        for f in sorted(tf, key=lambda f: SEV_ORDER.index(f["severity"])):
            tr2 += (f'<tr><td>{sev_badge(f["severity"])}</td>'
                    f'<td class="sc">{f["score"]:.1f}</td>'
                    f'<td>{esc(f["desc"])}</td>'
                    f'<td><code>{esc(f["source"])}</code></td>'
                    f'<td class="ev">{esc(f["evidence"])}</td></tr>')
        if not tr2:
            tr2 = "<tr><td colspan='5'>Sin hallazgos</td></tr>"

        tools_html = ""
        p = res.get("passive", {})
        tools_html += code_block("WHOIS",    p.get("whois", ""),    f"{tid}_w")
        tools_html += code_block("NSLookup", p.get("nslookup", ""), f"{tid}_n")
        tools_html += code_block("Nmap — salida completa",
                                 res.get("nmap", {}).get("raw", ""), f"{tid}_nm")
        web = res.get("web", {})
        if web:
            tools_html += code_block("Nikto",   web.get("nikto", ""),      f"{tid}_nk")
            tools_html += code_block("WhatWeb", web.get("whatweb", ""),    f"{tid}_ww")
            tools_html += code_block("Gobuster / DirBuster",
                                     web.get("dirbuster", ""), f"{tid}_gb")
        smb = res.get("smb", {})
        if smb:
            tools_html += code_block("Enum4Linux", smb.get("enum4linux", ""), f"{tid}_e4")
            tools_html += code_block("Nmap SMB",   smb.get("nmap_smb", ""),   f"{tid}_sm")
        ftp = res.get("ftp", {})
        if ftp:
            tools_html += code_block("Nmap FTP", ftp.get("nmap_ftp", ""), f"{tid}_ft")
        ssh = res.get("ssh", {})
        if ssh:
            k = "ssh_audit" if "ssh_audit" in ssh else "nmap_ssh"
            tools_html += code_block("SSH Audit", ssh.get(k, ""), f"{tid}_sh")
        mysql = res.get("mysql", {})
        if mysql:
            tools_html += code_block("SQLMap",     mysql.get("sqlmap", ""),     f"{tid}_sq")
            tools_html += code_block("Nmap MySQL", mysql.get("nmap_mysql", ""), f"{tid}_my")
        if "nikto_extra" in res:
            tools_html += code_block("Nikto extendido", res["nikto_extra"], f"{tid}_nx")

        crit_cnt = sum(1 for f in tf if f["severity"] == "Critical")
        tsecs += f"""<div class="tsec">
  <div class="thdr">
    <div><span class="ticon">◈</span><span class="tname">{esc(target)}</span>
      <span class="tbadge">{len(op)} puertos</span>
      <span class="tbadge" style="background:#e63946;color:#fff">{crit_cnt} críticos</span></div>
    <button class="cbtn" onclick="ts('{tid}_b')">Contraer / Expandir</button>
  </div>
  <div class="tbody" id="{tid}_b">
    <div class="g2">
      <div><h3 class="stitle">🌐 Registros DNS</h3>
        <table class="dt"><thead><tr><th>Tipo</th><th>Valor</th></tr></thead>
        <tbody>{dns_rows}</tbody></table></div>
      <div><h3 class="stitle">🔌 Puertos Abiertos</h3>
        <table class="dt"><thead><tr><th>Puerto</th><th>Servicio</th></tr></thead>
        <tbody>{pr}</tbody></table></div>
    </div>
    <h3 class="stitle">🎯 Hallazgos CVSS — {esc(target)}</h3>
    <div class="tw"><table class="dt ft">
      <thead><tr><th>Severidad</th><th>Score</th><th>Descripción</th>
      <th>Fuente</th><th>Evidencia</th></tr></thead>
      <tbody>{tr2}</tbody></table></div>
    <h3 class="stitle">🛠 Salida de herramientas</h3>
    {tools_html}
  </div>
</div>"""

    # ── stat cards ───────────────────────────────────────────────
    stat_cards = ""
    for sev, lbl, var in [
        ("Critical", "Críticos", "crit"), ("High",   "Altos",  "high"),
        ("Medium",   "Medios",   "med"),  ("Low",    "Bajos",  "low"),
        ("Info",     "Info",     "info"),
    ]:
        stat_cards += (f'<div class="sc-card" style="--cc:var(--{var})">'
                       f'<div class="scn">{counts[sev]}</div>'
                       f'<div class="scl">{lbl}</div></div>')

    # ── FIX: sbars era un string, no una lista → no usar "".join([sbars]) ──
    sbars_html = (sbars if sbars
                  else '<span style="color:var(--tx2);font-size:13px">Sin hallazgos detectados</span>')

    # ── HTML completo ────────────────────────────────────────────
    doc = f"""<!DOCTYPE html>
<html lang="es"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TANNERS — Reporte de Reconocimiento</title>
<style>
:root{{--bg:#0d1117;--bg2:#161b22;--bg3:#1c2128;--bd:#30363d;
  --tx:#e6edf3;--tx2:#8b949e;--ac:#58a6ff;
  --crit:#e63946;--high:#f4793b;--med:#f4d03f;--low:#4caf50;--info:#64b5f6;
  --r:8px;--fn:'Cascadia Code','Fira Code','Courier New',monospace}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--tx);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;line-height:1.6}}
.topbar{{background:var(--bg2);border-bottom:1px solid var(--bd);padding:0 32px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;height:56px}}
.logo{{font-family:var(--fn);font-size:18px;font-weight:700;color:var(--ac);letter-spacing:2px}}
.tmeta{{color:var(--tx2);font-size:12px;text-align:right}}
.wrap{{max-width:1400px;margin:0 auto;padding:32px 24px}}
.hero{{background:linear-gradient(135deg,#1a2332,#0d1117);border:1px solid var(--bd);border-radius:var(--r);padding:32px;margin-bottom:28px}}
.htitle{{font-family:var(--fn);font-size:26px;color:var(--ac);letter-spacing:4px;margin-bottom:4px}}
.hsub{{color:var(--tx2);font-size:13px;margin-bottom:20px}}
.hmeta{{display:flex;gap:28px;flex-wrap:wrap;margin-bottom:20px}}
.hmi{{display:flex;flex-direction:column}}
.hml{{font-size:11px;color:var(--tx2);text-transform:uppercase;letter-spacing:1px}}
.hmv{{font-size:15px;font-weight:600}}
.sg{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:24px}}
.sc-card{{background:var(--bg3);border:1px solid var(--bd);border-radius:var(--r);padding:16px;text-align:center;border-top:3px solid var(--cc,var(--bd))}}
.scn{{font-size:34px;font-weight:700;color:var(--cc,var(--tx));line-height:1}}
.scl{{font-size:11px;color:var(--tx2);text-transform:uppercase;letter-spacing:1px;margin-top:4px}}
.sbr{{display:flex;align-items:center;gap:10px;margin-bottom:8px}}
.slbl{{width:68px;font-size:12px;color:var(--tx2)}}
.strk{{flex:1;background:var(--bg3);border-radius:4px;height:8px;overflow:hidden}}
.sfil{{height:100%;border-radius:4px;transition:width .6s ease}}
.scnt{{width:28px;text-align:right;font-size:12px;color:var(--tx2)}}
.tabs{{display:flex;gap:4px;margin-bottom:20px;border-bottom:1px solid var(--bd)}}
.tb{{padding:8px 20px;border:none;background:transparent;color:var(--tx2);cursor:pointer;border-radius:var(--r) var(--r) 0 0;font-size:13px;border-bottom:2px solid transparent;transition:all .2s}}
.tb:hover{{color:var(--tx)}}
.tb.on{{color:var(--ac);border-bottom-color:var(--ac);background:var(--bg2)}}
.tp{{display:none}}.tp.on{{display:block}}
.tw{{overflow-x:auto;margin-bottom:20px}}
.dt{{width:100%;border-collapse:collapse;font-size:13px}}
.dt th{{background:var(--bg3);color:var(--tx2);padding:10px 12px;text-align:left;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--bd)}}
.dt td{{padding:9px 12px;border-bottom:1px solid var(--bd);vertical-align:top}}
.dt tr:hover td{{background:var(--bg2)}}
.dt code{{background:var(--bg3);padding:2px 6px;border-radius:4px;font-family:var(--fn);font-size:12px}}
.sc{{font-weight:700;font-size:15px;color:var(--ac)}}
.ev{{font-family:var(--fn);font-size:11px;color:var(--tx2);max-width:280px;word-break:break-all}}
.vec{{font-size:10px!important}}
.badge{{display:inline-block;padding:2px 9px;border-radius:12px;font-size:11px;font-weight:700;letter-spacing:.5px;white-space:nowrap}}
.tsec{{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--r);margin-bottom:16px;overflow:hidden}}
.thdr{{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;background:var(--bg3);border-bottom:1px solid var(--bd)}}
.ticon{{color:var(--ac);margin-right:8px;font-size:15px}}
.tname{{font-size:15px;font-weight:700;font-family:var(--fn)}}
.tbadge{{display:inline-block;margin-left:8px;padding:2px 8px;border-radius:10px;font-size:11px;background:var(--bg);color:var(--tx2)}}
.tbody{{padding:20px}}
.cbtn{{background:var(--bg);border:1px solid var(--bd);color:var(--tx2);padding:5px 12px;border-radius:var(--r);cursor:pointer;font-size:12px}}
.cbtn:hover{{color:var(--tx);border-color:var(--ac)}}
.stitle{{font-size:12px;font-weight:600;color:var(--tx2);text-transform:uppercase;letter-spacing:1px;margin:18px 0 8px}}
.g2{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:8px}}
@media(max-width:768px){{.g2{{grid-template-columns:1fr}}}}
.card{{background:var(--bg);border:1px solid var(--bd);border-radius:var(--r);margin-bottom:8px;overflow:hidden}}
.card-hdr{{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;cursor:pointer;user-select:none;font-size:13px;font-weight:600;color:var(--tx2);background:var(--bg3)}}
.card-hdr:hover{{color:var(--tx)}}
.chev{{transition:transform .2s}}
.card.open .chev{{transform:rotate(180deg)}}
.card-body{{display:none;padding:14px;border-top:1px solid var(--bd)}}
.card.open .card-body{{display:block}}
.card-body pre{{font-family:var(--fn);font-size:12px;line-height:1.5;color:var(--tx2);white-space:pre-wrap;word-break:break-all;max-height:400px;overflow-y:auto}}
.srch{{width:100%;background:var(--bg2);border:1px solid var(--bd);color:var(--tx);padding:10px 16px;border-radius:var(--r);font-size:14px;margin-bottom:14px;outline:none}}
.srch:focus{{border-color:var(--ac)}}
.nof{{text-align:center;padding:40px;color:var(--tx2)}}
.ft{{background:var(--bg)}}
.footer{{text-align:center;color:var(--tx2);font-size:12px;padding:28px 0 16px;border-top:1px solid var(--bd);margin-top:36px}}
.footer code{{color:var(--ac)}}
.hdr-box{{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--r);padding:14px 20px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between}}
</style>
</head><body>

<div class="topbar">
  <div class="logo">⬡ TANNERS</div>
  <div class="tmeta">Security Reconnaissance Tool v2.1<br>Generado: {esc(ts)}</div>
</div>

<div class="wrap">

<div class="hero">
  <div class="htitle">TANNERS</div>
  <div class="hsub">Security Reconnaissance &amp; Vulnerability Assessment Report</div>
  <div class="hmeta">
    <div class="hmi"><span class="hml">Objetivos</span><span class="hmv">{len(targets)}</span></div>
    <div class="hmi"><span class="hml">Hallazgos</span><span class="hmv">{total}</span></div>
    <div class="hmi"><span class="hml">Generado</span><span class="hmv">{esc(ts)}</span></div>
    <div class="hmi"><span class="hml">Clasificación</span><span class="hmv" style="color:var(--crit)">CONFIDENCIAL</span></div>
  </div>
  <div class="sg">{stat_cards}</div>
  <div>{sbars_html}</div>
</div>

<div class="tabs">
  <button class="tb on" onclick="swt('tf',this)">🎯 Hallazgos CVSS</button>
  <button class="tb" onclick="swt('tt',this)">🖥 Detalle por Target</button>
</div>

<div class="tp on" id="tf">
  <input class="srch" id="fsrch" placeholder="🔍 Filtrar hallazgos..." oninput="flt()">
  <div class="tw">
    {"<table class='dt ft' id='ftbl'><thead><tr><th>Target</th><th>Severidad</th><th>Score</th><th>Descripción</th><th>Fuente</th><th>Vector CVSS</th><th>Evidencia</th></tr></thead><tbody>" + grow + "</tbody></table>" if grow else '<div class="nof">✅ Sin hallazgos detectados. Verificar manualmente.</div>'}
  </div>
</div>

<div class="tp" id="tt">
  {tsecs}
</div>

<div class="footer">
  Generado por <code>TANNERS</code> v2.1 &nbsp;·&nbsp; {esc(ts)}<br>
  Información confidencial — distribución restringida.<br>
  Los hallazgos deben verificarse manualmente. Las herramientas automatizadas pueden generar falsos positivos.
</div>

</div>

<script>
function swt(id,btn){{
  document.querySelectorAll('.tp').forEach(p=>p.classList.remove('on'));
  document.querySelectorAll('.tb').forEach(b=>b.classList.remove('on'));
  document.getElementById(id).classList.add('on');
  btn.classList.add('on');
}}
function tog(id){{document.getElementById(id).classList.toggle('open');}}
function ts(id){{
  const el=document.getElementById(id);
  el.style.display=(el.style.display==='none')?'':'none';
}}
function flt(){{
  const q=document.getElementById('fsrch').value.toLowerCase();
  document.querySelectorAll('#ftbl tbody tr').forEach(r=>{{
    r.style.display=r.innerText.toLowerCase().includes(q)?'':'none';
  }});
}}
window.addEventListener('load',()=>{{
  document.querySelectorAll('.sfil').forEach(el=>{{
    const w=el.style.width; el.style.width='0';
    setTimeout(()=>{{el.style.width=w;}},120);
  }});
}});
</script>
</body></html>"""

    Path(output_path).write_text(doc, encoding="utf-8")
    return True


# ══════════════════════════════════════════════════════════════════
#  DEPENDENCIAS
# ══════════════════════════════════════════════════════════════════
def check_dependencies():
    hdr("VERIFICANDO DEPENDENCIAS")
    req = ["nmap", "whois", "dig", "nslookup"]
    opt = ["nikto", "whatweb", "gobuster", "dirb",
           "enum4linux", "ssh-audit", "sqlmap"]
    info("Herramientas requeridas:")
    missing = check_tools(req)
    info("\nHerramientas opcionales:")
    check_tools(opt)
    return missing


# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════
def main():
    banner()
    parser = argparse.ArgumentParser(
        description="TANNERS v2.1 — Reconocimiento y escaneo de vulnerabilidades",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 tanners.py example.com
  python3 tanners.py 192.168.1.0/24
  python3 tanners.py 10.0.0.1 10.0.0.2 10.0.0.5
  python3 tanners.py targets.txt
  python3 tanners.py example.com -o reporte.html
  python3 tanners.py example.com --check-only
  python3 tanners.py example.com --skip-passive --ports-only
        """
    )
    parser.add_argument("targets", nargs="*",
                        help="IP, dominio, CIDR (192.168.1.0/24) o archivo con targets")
    parser.add_argument("-o", "--output", default=None,
                        help="Ruta del dashboard HTML (default: tanners_<fecha>.html)")
    parser.add_argument("--check-only", action="store_true",
                        help="Solo verificar dependencias")
    parser.add_argument("--skip-passive", action="store_true",
                        help="Omitir reconocimiento pasivo")
    parser.add_argument("--ports-only", action="store_true",
                        help="Solo nmap, sin análisis de servicios")

    args    = parser.parse_args()
    missing = check_dependencies()

    if args.check_only:
        if missing:
            print(f"\n{C.YELLOW}Instala con:{C.RESET} sudo apt install {' '.join(missing)}")
        sys.exit(0)

    if not args.targets:
        parser.print_help()
        sys.exit(1)

    # ── Expandir y validar targets ────────────────────────────────
    all_targets = []
    for raw in args.targets:
        all_targets.extend(expand_targets(raw))
    all_targets = list(dict.fromkeys(all_targets))   # dedup

    # ── FIX: rechazar targets que no sean IP/dominio válidos ──────
    safe_targets = []
    for t in all_targets:
        if validate_target(t):
            safe_targets.append(t)
        else:
            err(f"Target inválido o potencialmente inseguro, ignorado: {t!r}")
    all_targets = safe_targets

    if not all_targets:
        err("No quedan targets válidos. Abortando.")
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output    = args.output or f"tanners_{timestamp}.html"

    preview = ", ".join(all_targets[:6]) + ("..." if len(all_targets) > 6 else "")
    print(f"\n  {C.BOLD}Targets ({len(all_targets)}):{C.RESET} {C.CYAN}{preview}{C.RESET}")
    print(f"  {C.BOLD}Output :{C.RESET} {C.CYAN}{output}{C.RESET}\n")

    if missing:
        warn(f"Herramientas faltantes: {', '.join(missing)}")
        warn("Instálalas con: sudo apt install " + " ".join(missing))

    all_results = {}
    for idx, target in enumerate(all_targets):
        print(f"\n{C.BOLD}{C.MAGENTA}  ══ TARGET {idx + 1}/{len(all_targets)}: {target} ══{C.RESET}")
        res = {"target": target, "timestamp": timestamp, "findings": []}

        if not args.skip_passive:
            phase_passive(target, res)

        open_ports = phase_nmap(target, res)

        if not args.ports_only:
            phase_web(target, open_ports, res)
            phase_smb(target, open_ports, res)
            phase_ftp(target, open_ports, res)
            phase_ssh(target, open_ports, res)
            phase_mysql(target, open_ports, res)
            phase_nikto_extra(target, open_ports, res)

        all_results[target] = res
        finds = res.get("findings", [])
        crits = sum(1 for f in finds if f["severity"] == "Critical")
        highs = sum(1 for f in finds if f["severity"] == "High")
        print(f"\n  {C.GREEN}✔{C.RESET}  {target} — "
              f"{C.RED}{crits} críticos{C.RESET} / "
              f"{C.YELLOW}{highs} altos{C.RESET} / "
              f"{len(finds)} hallazgos totales")

    # ── Dashboard HTML ────────────────────────────────────────────
    hdr("GENERANDO DASHBOARD HTML")
    info(f"Escribiendo {output}...")
    generate_html(all_results, output)
    size_kb = Path(output).stat().st_size // 1024
    ok(f"Dashboard: {C.CYAN}{output}{C.RESET} ({size_kb} KB)")

    total_f = sum(len(r.get("findings", [])) for r in all_results.values())
    total_c = sum(
        sum(1 for f in r.get("findings", []) if f["severity"] == "Critical")
        for r in all_results.values()
    )

    print(f"""
  {C.BOLD}{'─' * 52}{C.RESET}
  {C.GREEN}{C.BOLD}  ✔  Reconocimiento completado{C.RESET}
  {C.BOLD}{'─' * 52}{C.RESET}
    Targets escaneados : {C.CYAN}{len(all_results)}{C.RESET}
    Hallazgos totales  : {C.WHITE}{total_f}{C.RESET}
    Críticos           : {C.RED}{total_c}{C.RESET}
    Dashboard          : {C.CYAN}{output}{C.RESET}
  {C.BOLD}{'─' * 52}{C.RESET}
""")


if __name__ == "__main__":
    main()
