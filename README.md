# Network Security Voice Scanner

A voice-first network security tool built with **VAPI** + **Claude Sonnet** + **nmap**.

Speak to the assistant and it will scan your WiFi network, identify connected devices, detect open ports, and flag security risks — all reported back to you by voice.

## Architecture

```
Browser (VAPI Web SDK)
        │  voice
        ▼
   VAPI Platform  ──── Claude Sonnet (LLM) ────► runNetworkScan tool call
        │
        │  POST /webhook
        ▼
  FastAPI Server  (localhost:8000, exposed via cloudflared tunnel)
        │
        ▼
    python-nmap  →  nmap binary
        │
        ▼
  Structured results + voice summary  ──► VAPI  ──► spoken response
```

## Prerequisites

| Requirement | Install |
|------------|---------|
| Python 3.12+ | `brew install python` |
| nmap | `brew install nmap` *or* download the macOS app from nmap.org |
| cloudflared | `brew install cloudflared` — free, no account needed |
| VAPI account | [dashboard.vapi.ai](https://dashboard.vapi.ai) |

## Setup

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Install cloudflared (exposes the local webhook to VAPI)
brew install cloudflared

# 3. Create your .env file
cp .env.example .env
```

Edit `.env` and fill in:
- `VAPI_API_KEY` — your **private** API key from the VAPI dashboard
- `VAPI_PUBLIC_KEY` — your **public** API key (used in the browser)

## Running

```bash
python main.py
```

Then open **http://localhost:8000** in your browser, click **Start Session**, and hold the orb to speak.

### Example commands

| What you say | What happens |
|---|---|
| "scan my network" | Full nmap scan of your /24 subnet |
| "what devices did you find?" | Lists all discovered hosts |
| "which risks are critical?" | Focuses on CRITICAL severity issues |
| "tell me more about the router" | Elaborates on a specific device |

## Security notes

- The scan runs **on your machine** — no network data leaves except to VAPI's LLM API
- nmap requires no special privileges for the TCP connect + service version scan used here
- OS fingerprinting (`-O`) is intentionally omitted to avoid needing sudo
- Device models are inferred from service banners and product strings, not MAC OUI (which requires root ARP scan)

## Scanned ports & risk levels

| Port | Service | Severity |
|------|---------|----------|
| 23 | Telnet | CRITICAL |
| 445 | SMB | CRITICAL |
| 21 | FTP | HIGH |
| 135/139 | Windows RPC/NetBIOS | HIGH |
| 1433 | MSSQL | HIGH |
| 3306 | MySQL | HIGH |
| 3389 | RDP | HIGH |
| 5900 | VNC | HIGH |
| 22 | SSH | MEDIUM |
| 25 | SMTP | MEDIUM |
| 53 | DNS | LOW |
| 80/8080 | HTTP | LOW |
| 443/8443 | HTTPS | LOW |
