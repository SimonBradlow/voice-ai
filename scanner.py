"""
Network scanner using nmap. Discovers devices, detects open ports,
and flags security risks on the local WiFi network.
"""

import os
import shutil
import socket
import ipaddress
import nmap

# Support both the nmap.app macOS install and a Homebrew/system install
_APP_NMAP   = "/Applications/nmap.app/Contents/Resources/bin/nmap"
_BREW_NMAP  = shutil.which("nmap") or "/opt/homebrew/bin/nmap"
NMAP_PATH   = _APP_NMAP if os.path.exists(_APP_NMAP) else _BREW_NMAP

# Ports to scan and their risk profiles
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
    1433: ("MSSQL",      "HIGH",     "SQL Server database exposed to the network"),
    3306: ("MySQL",      "HIGH",     "MySQL database exposed to the network"),
    3389: ("RDP",        "HIGH",     "Remote Desktop Protocol — common brute-force target"),
    5900: ("VNC",        "HIGH",     "VNC remote desktop — often poorly secured"),
    8080: ("HTTP-Alt",   "LOW",      "Web server on non-standard port"),
    8443: ("HTTPS-Alt",  "LOW",      "HTTPS on non-standard port"),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

SCAN_PORTS = ",".join(str(p) for p in sorted(RISKY_PORTS.keys()))


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
    Run a two-phase nmap scan:
      1. Ping sweep — fast host discovery
      2. Port scan + service detection on live hosts

    Returns a structured dict with devices and security risks.
    """
    network, local_ip = get_local_network()
    target = target or network

    nm = nmap.PortScanner(nmap_search_path=(NMAP_PATH,))

    # ── Phase 1: host discovery ──────────────────────────────────────────────
    try:
        nm.scan(hosts=target, arguments="-sn -T5 --host-timeout 5")
    except Exception as exc:
        return {"error": f"Host discovery failed: {exc}"}

    live_hosts = [h for h in nm.all_hosts() if nm[h].state() == "up"]

    if not live_hosts:
        return {
            "network": target,
            "local_ip": local_ip,
            "hosts_found": 0,
            "devices": [],
            "security_risks": [],
            "critical_count": 0,
            "high_count": 0,
        }

    # ── Phase 2: port scan on live hosts (no -sV to keep it fast) ───────────
    hosts_arg = " ".join(live_hosts)
    scan_args = (
        f"-sT -T5 --open "
        f"-p {SCAN_PORTS} "
        f"--host-timeout 8 "
        f"--min-rate 500 -n"
    )

    try:
        nm.scan(hosts=hosts_arg, arguments=scan_args)
    except Exception as exc:
        return {"error": f"Port scan failed: {exc}"}

    devices = []
    all_risks = []

    for host in nm.all_hosts():
        h = nm[host]
        hostname = h.hostname() or host

        open_ports: list[dict] = []
        host_risks: list[dict] = []
        vendor_hints: list[str] = []

        for proto in h.all_protocols():
            for port in sorted(h[proto].keys()):
                svc = h[proto][port]
                if svc["state"] != "open":
                    continue

                product = svc.get("product", "")
                version = svc.get("version", "")
                if product:
                    vendor_hints.append(product)

                open_ports.append({
                    "port": port,
                    "service": svc.get("name", "unknown"),
                    "product": product,
                    "version": version,
                })

                if port in RISKY_PORTS:
                    label, severity, description = RISKY_PORTS[port]
                    risk = {
                        "host": host,
                        "hostname": hostname,
                        "port": port,
                        "service": label,
                        "severity": severity,
                        "description": description,
                    }
                    host_risks.append(risk)
                    all_risks.append(risk)

        devices.append({
            "ip": host,
            "hostname": hostname,
            "vendor": vendor_hints[0] if vendor_hints else "Unknown device",
            "open_ports": open_ports,
            "risks": host_risks,
        })

    all_risks.sort(key=lambda r: SEVERITY_ORDER.get(r["severity"], 99))

    return {
        "network": target,
        "local_ip": local_ip,
        "hosts_found": len(devices),
        "devices": devices,
        "security_risks": all_risks,
        "critical_count": sum(1 for r in all_risks if r["severity"] == "CRITICAL"),
        "high_count":     sum(1 for r in all_risks if r["severity"] == "HIGH"),
    }


def _voice_ip(ip: str) -> str:
    """Format an IP address for natural TTS reading: 192.168.1.1 → 192 168 1 1"""
    return ip.replace(".", " ")


def format_for_voice(result: dict) -> str:
    """Convert a scan result dict into a concise, voice-friendly summary."""
    if "error" in result:
        return f"The scan encountered an error: {result['error']}. Please make sure nmap is installed and try again."

    hosts = result["hosts_found"]
    risks = result["security_risks"]
    critical = result["critical_count"]
    high = result["high_count"]
    network = result["network"]

    parts: list[str] = []

    parts.append(
        f"Scan complete. I found {hosts} device{'s' if hosts != 1 else ''} "
        f"on your network."
    )

    # Per-device summary — skip devices with no open ports to keep it brief
    flagged_devs = [d for d in result["devices"] if d["open_ports"]]
    for dev in flagged_devs[:8]:
        ip = _voice_ip(dev["ip"])
        vendor = dev["vendor"]
        ports = dev["open_ports"]
        port_strs = [f"port {p['port']} ({p['service']})" for p in ports[:3]]
        line = f"Device {ip}"
        if vendor != "Unknown device":
            line += f", running {vendor}"
        line += f". Open: {', '.join(port_strs)}"
        if len(ports) > 3:
            line += f" and {len(ports) - 3} more"
        parts.append(line + ".")

    # Security summary
    if not risks:
        parts.append("No significant security risks detected on this network.")
    else:
        parts.append(
            f"Security findings: {len(risks)} issue{'s' if len(risks) != 1 else ''} detected."
        )
        if critical:
            parts.append(
                f"{critical} CRITICAL issue{'s' if critical != 1 else ''} require immediate attention."
            )
        if high:
            parts.append(
                f"{high} HIGH severity issue{'s' if high != 1 else ''} should be addressed soon."
            )

        for risk in risks[:6]:
            parts.append(
                f"On device {_voice_ip(risk['host'])}, port {risk['port']} ({risk['service']}) "
                f"is {risk['severity']}: {risk['description']}."
            )

        if len(risks) > 6:
            parts.append(
                f"Plus {len(risks) - 6} additional lower-severity findings."
            )

    return " ".join(parts)
