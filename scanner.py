"""
Network scanner using nmap. Discovers devices, detects open ports,
flags security risks, fingerprints device types, and runs targeted
vulnerability scans on individual hosts.
"""

import re
import socket
import ipaddress
import nmap

NMAP_PATH = "/Applications/nmap.app/Contents/Resources/bin/nmap"

# Ports scanned on every host during a network sweep
RISKY_PORTS = {
    21:   ("FTP",        "HIGH",     "Unencrypted file transfer — credentials sent in plain text"),
    22:   ("SSH",        "MEDIUM",   "Remote shell access — ensure key-based auth and no root login"),
    23:   ("Telnet",     "CRITICAL", "Completely unencrypted remote access — replace with SSH immediately"),
    25:   ("SMTP",       "MEDIUM",   "Email server — could relay spam if misconfigured"),
    53:   ("DNS",        "LOW",      "DNS server — ensure it is not an open resolver"),
    80:   ("HTTP",       "LOW",      "Unencrypted web server — consider forcing HTTPS"),
    135:  ("RPC",        "HIGH",     "Windows RPC — common attack vector"),
    139:  ("NetBIOS",    "HIGH",     "Windows file sharing — frequently targeted by malware"),
    443:  ("HTTPS",      "LOW",      "Encrypted web server — verify certificate is valid"),
    445:  ("SMB",        "CRITICAL", "Windows file sharing — ransomware vector (WannaCry, NotPetya)"),
    548:  ("AFP",        "LOW",      "Apple Filing Protocol — Mac file sharing"),
    554:  ("RTSP",       "MEDIUM",   "Streaming camera or media server exposed to the network"),
    631:  ("IPP",        "LOW",      "Network printer (IPP)"),
    1433: ("MSSQL",      "HIGH",     "SQL Server database exposed to the network"),
    3306: ("MySQL",      "HIGH",     "MySQL database exposed to the network"),
    3389: ("RDP",        "HIGH",     "Remote Desktop Protocol — common brute-force target"),
    5900: ("VNC",        "HIGH",     "VNC remote desktop — often poorly secured"),
    8080: ("HTTP-Alt",   "LOW",      "Web server on non-standard port"),
    8443: ("HTTPS-Alt",  "LOW",      "HTTPS on non-standard port"),
    9100: ("JetDirect",  "LOW",      "HP printer — JetDirect print service"),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SCAN_PORTS     = ",".join(str(p) for p in sorted(RISKY_PORTS.keys()))


# ── Device fingerprinting ─────────────────────────────────────────────────────

def guess_device(ip: str, hostname: str, ports: set[int], products: list[str]) -> dict:
    """
    Heuristically identify device type and manufacturer from hostname,
    open ports, and any service product strings nmap grabbed.
    Returns {"type": str, "make": str}.
    """
    hn  = (hostname or "").lower()
    raw = hn if hn != ip.lower() else ""
    prd = " ".join(p.lower() for p in products)

    # ── Product string matches (most reliable) ──────────────────────────────
    product_rules = [
        (("synology", "diskstation"),          "NAS",            "Synology"),
        (("qnap",),                            "NAS",            "QNAP"),
        (("plex",),                            "Media Server",   "Plex"),
        (("apple airport", "airport extreme"), "Router",         "Apple"),
        (("airport",),                         "Router",         "Apple"),
        (("ubiquiti", "unifi"),                "Router/AP",      "Ubiquiti"),
        (("mikrotik",),                        "Router",         "MikroTik"),
        (("openwrt",),                         "Router",         "OpenWrt"),
        (("dd-wrt",),                          "Router",         "DD-WRT"),
        (("philips hue",),                     "Smart Light",    "Philips"),
        (("ring",),                            "Smart Home",     "Ring"),
        (("nest",),                            "Smart Home",     "Google/Nest"),
        (("microsoft iis",),                   "Windows Server", "Microsoft"),
        (("apache",),                          "Linux Server",   "Apache"),
        (("nginx",),                           "Linux Server",   "Nginx"),
        (("openssh",),                         "Linux Server",   "Unknown"),
        (("hp ",  "hewlett"),                  "Printer",        "HP"),
        (("canon",),                           "Printer",        "Canon"),
        (("epson",),                           "Printer",        "Epson"),
        (("brother",),                         "Printer",        "Brother"),
    ]
    for keywords, dtype, make in product_rules:
        if any(k in prd for k in keywords):
            return {"type": dtype, "make": make}

    # ── Hostname pattern matches ─────────────────────────────────────────────
    hostname_rules = [
        (("iphone", "ipad"),                   "Mobile",         "Apple"),
        (("macbook", "imac", "mac-mini",
          "mac-pro", "macpro"),                "Computer",       "Apple"),
        (("apple",),                           "Apple Device",   "Apple"),
        (("android", "pixel", "samsung",
          "galaxy"),                           "Mobile",         "Android"),
        (("xbox",),                            "Console",        "Microsoft"),
        (("playstation", "ps4", "ps5"),        "Console",        "Sony"),
        (("nintendo", "switch"),               "Console",        "Nintendo"),
        (("printer", "print"),                 "Printer",        "Unknown"),
        (("ring-",),                           "Smart Home",     "Ring"),
        (("echo-", "alexa"),                   "Smart Speaker",  "Amazon"),
        (("nest",),                            "Smart Home",     "Google"),
        (("hue",),                             "Smart Light",    "Philips"),
        (("synology", "diskstation"),          "NAS",            "Synology"),
        (("qnap",),                            "NAS",            "QNAP"),
        (("router", "gateway", "modem"),       "Router",         "Unknown"),
        (("ubnt", "unifi"),                    "Router/AP",      "Ubiquiti"),
        (("raspberrypi", "raspberry"),         "SBC",            "Raspberry Pi"),
        (("server", "srv-", "nas-"),           "Server",         "Unknown"),
        (("camera", "cam-", "nvr", "dvr"),     "Camera/NVR",     "Unknown"),
    ]
    for keywords, dtype, make in hostname_rules:
        if any(k in raw for k in keywords):
            return {"type": dtype, "make": make}

    # ── Port combination heuristics ─────────────────────────────────────────
    if {135, 445}.issubset(ports) or {139, 445}.issubset(ports):
        return {"type": "Windows PC", "make": "Microsoft"}
    if 3389 in ports:
        return {"type": "Windows PC/Server", "make": "Microsoft"}
    if 548 in ports:
        return {"type": "Computer", "make": "Apple"}
    if {9100}.issubset(ports) or {631, 515} & ports:
        return {"type": "Printer", "make": "Unknown"}
    if 554 in ports:
        return {"type": "Camera/NVR", "make": "Unknown"}
    if 53 in ports and (80 in ports or 443 in ports):
        return {"type": "Router/Gateway", "make": "Unknown"}
    if 22 in ports and not ({80, 443, 8080} & ports):
        return {"type": "Linux Server", "make": "Unknown"}
    if {80, 443} & ports:
        return {"type": "Server/Device", "make": "Unknown"}

    return {"type": "Unknown", "make": "Unknown"}


# ── Network scan ──────────────────────────────────────────────────────────────

def get_local_network() -> tuple[str, str]:
    """Detect the local network CIDR and current IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        network = str(ipaddress.IPv4Network(f"{local_ip}/24", strict=False))
        return network, local_ip
    except Exception:
        return "192.168.1.0/24", "unknown"


def run_network_scan(target: str | None = None) -> dict:
    """
    Two-phase nmap scan: ping sweep then port scan.
    Returns structured dict with devices (including fingerprint) and risks.
    """
    network, local_ip = get_local_network()
    target = target or network

    nm = nmap.PortScanner(nmap_search_path=(NMAP_PATH,))

    # Phase 1: host discovery
    try:
        nm.scan(hosts=target, arguments="-sn -T5 --host-timeout 5")
    except Exception as exc:
        return {"error": f"Host discovery failed: {exc}"}

    live_hosts = [h for h in nm.all_hosts() if nm[h].state() == "up"]

    if not live_hosts:
        return {
            "network": target, "local_ip": local_ip,
            "hosts_found": 0, "devices": [],
            "security_risks": [], "critical_count": 0, "high_count": 0,
        }

    # Phase 2: port scan on live hosts
    hosts_arg = " ".join(live_hosts)
    scan_args  = f"-sT -T5 --open -p {SCAN_PORTS} --host-timeout 8 --min-rate 500 -n"

    try:
        nm.scan(hosts=hosts_arg, arguments=scan_args)
    except Exception as exc:
        return {"error": f"Port scan failed: {exc}"}

    devices   = []
    all_risks = []

    for host in nm.all_hosts():
        h        = nm[host]
        hostname = h.hostname() or host

        open_ports: list[dict] = []
        host_risks: list[dict] = []
        products:   list[str]  = []

        for proto in h.all_protocols():
            for port in sorted(h[proto].keys()):
                svc = h[proto][port]
                if svc["state"] != "open":
                    continue
                product = svc.get("product", "")
                version = svc.get("version", "")
                if product:
                    products.append(product)
                open_ports.append({
                    "port": port, "service": svc.get("name", "unknown"),
                    "product": product, "version": version,
                })
                if port in RISKY_PORTS:
                    label, severity, description = RISKY_PORTS[port]
                    risk = {
                        "host": host, "hostname": hostname,
                        "port": port, "service": label,
                        "severity": severity, "description": description,
                    }
                    host_risks.append(risk)
                    all_risks.append(risk)

        port_set   = {p["port"] for p in open_ports}
        fingerprint = guess_device(host, hostname, port_set, products)
        max_sev    = min(
            (SEVERITY_ORDER[r["severity"]] for r in host_risks),
            default=99,
        )
        risk_label = {0: "CRITICAL", 1: "HIGH", 2: "MEDIUM", 3: "LOW"}.get(max_sev, "CLEAN")

        devices.append({
            "ip":          host,
            "hostname":    hostname if hostname != host else "",
            "device_type": fingerprint["type"],
            "make":        fingerprint["make"],
            "open_ports":  open_ports,
            "risks":       host_risks,
            "risk_level":  risk_label,
        })

    all_risks.sort(key=lambda r: SEVERITY_ORDER.get(r["severity"], 99))

    return {
        "network":        target,
        "local_ip":       local_ip,
        "hosts_found":    len(devices),
        "devices":        devices,
        "security_risks": all_risks,
        "critical_count": sum(1 for r in all_risks if r["severity"] == "CRITICAL"),
        "high_count":     sum(1 for r in all_risks if r["severity"] == "HIGH"),
    }


# ── Vulnerability scan ────────────────────────────────────────────────────────

VULN_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,"
    "631,993,995,1433,1521,3306,3389,5432,5900,5985,6379,"
    "8080,8443,8888,9100,9200,27017"
)


def run_vuln_scan(ip: str) -> dict:
    """
    Targeted deep scan of a single host:
      - Full service version detection on common ports
      - Returns open services with versions for AI analysis
    """
    nm = nmap.PortScanner(nmap_search_path=(NMAP_PATH,))
    try:
        nm.scan(
            hosts=ip,
            arguments=f"-sT -sV -T4 --open -p {VULN_PORTS} --host-timeout 30",
        )
    except Exception as exc:
        return {"error": f"Vulnerability scan failed: {exc}", "ip": ip}

    if ip not in nm.all_hosts():
        return {"error": "Host did not respond", "ip": ip}

    h        = nm[ip]
    hostname = h.hostname() or ip
    services = []
    risks    = []

    for proto in h.all_protocols():
        for port in sorted(h[proto].keys()):
            svc = h[proto][port]
            if svc["state"] != "open":
                continue
            product = svc.get("product", "")
            version = svc.get("version", "")
            svc_name = svc.get("name", "unknown")
            services.append({
                "port":    port,
                "service": svc_name,
                "product": product,
                "version": version,
                "banner":  f"{product} {version}".strip(),
            })
            if port in RISKY_PORTS:
                label, severity, description = RISKY_PORTS[port]
                risks.append({
                    "port": port, "service": label,
                    "severity": severity, "description": description,
                    "version": f"{product} {version}".strip(),
                })

    risks.sort(key=lambda r: SEVERITY_ORDER.get(r["severity"], 99))
    return {
        "ip":       ip,
        "hostname": hostname,
        "services": services,
        "risks":    risks,
        "critical_count": sum(1 for r in risks if r["severity"] == "CRITICAL"),
        "high_count":     sum(1 for r in risks if r["severity"] == "HIGH"),
    }


# ── Voice formatting ──────────────────────────────────────────────────────────

def _voice_ip(ip: str) -> str:
    # Return the raw IP — OpenAI TTS reads dots as natural pauses between octets.
    return ip


def format_for_voice(result: dict) -> str:
    """Network scan → minimal voice summary. IPs intentionally omitted — they're in the table."""
    if "error" in result:
        return f"Scan failed: {result['error']}. Check that nmap is installed."

    hosts    = result["hosts_found"]
    risks    = result["security_risks"]
    critical = result["critical_count"]
    high     = result["high_count"]

    summary = f"Found {hosts} device{'s' if hosts != 1 else ''} on your network."

    if not risks:
        return summary + " No significant security risks detected."

    severity = []
    if critical:
        severity.append(f"{critical} critical")
    if high:
        severity.append(f"{high} high")
    med = sum(1 for r in risks if r["severity"] == "MEDIUM")
    low = sum(1 for r in risks if r["severity"] == "LOW")
    if med:
        severity.append(f"{med} medium")
    if low:
        severity.append(f"{low} low")

    summary += f" {len(risks)} security issue{'s' if len(risks) != 1 else ''} detected: {', '.join(severity)}."

    # Group risks by service name so AI can summarise without naming IPs
    from collections import Counter
    service_counts = Counter(r["service"] for r in risks)
    top = ", ".join(f"{svc} ({n})" for svc, n in service_counts.most_common(4))
    summary += f" Top findings: {top}."

    return summary


def format_vuln_for_voice(result: dict) -> str:
    """Vuln scan → minimal voice summary. No IPs or raw port numbers in the text."""
    if "error" in result:
        return f"Vulnerability scan failed: {result['error']}."

    services = result["services"]
    risks    = result["risks"]
    critical = result["critical_count"]
    high     = result["high_count"]

    summary = f"Deep scan complete. {len(services)} open service{'s' if len(services) != 1 else ''} found."

    if not risks:
        return summary + " No high-risk services detected."

    severity = []
    if critical:
        severity.append(f"{critical} critical")
    if high:
        severity.append(f"{high} high")
    summary += f" {len(risks)} risk{'s' if len(risks) != 1 else ''}: {', '.join(severity)}."

    # List risky services by name, not by port number
    for risk in risks[:5]:
        ver = f" ({risk['version']})" if risk.get("version") else ""
        summary += f" {risk['service']}{ver} is {risk['severity']}."

    # Versioned services for AI context
    versioned = [s for s in services if s["banner"]]
    if versioned:
        banners = "; ".join(f"{s['service']} — {s['banner']}" for s in versioned[:5])
        summary += f" Detected: {banners}."

    return summary
