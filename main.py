#!/usr/bin/env python3
"""
Entry point for the Network Security Voice Scanner.

Steps:
  1. Start a cloudflared tunnel so VAPI can reach the local webhook server
  2. Create a fresh VAPI assistant pointing at that tunnel URL
  3. Write the assistant ID + public key to static/config.json for the web UI
  4. Start the FastAPI server
"""

import json
import os
import re
import subprocess
import sys
import time

import uvicorn
from dotenv import load_dotenv

load_dotenv()

VAPI_API_KEY    = os.getenv("VAPI_API_KEY", "")
VAPI_PUBLIC_KEY = os.getenv("VAPI_PUBLIC_KEY", "")
PORT            = int(os.getenv("PORT", "8000"))


def start_cloudflared(port: int) -> tuple[str, subprocess.Popen]:
    """Start a cloudflared quick tunnel and return (public_url, process)."""
    proc = subprocess.Popen(
        ["cloudflared", "tunnel", "--url", f"http://localhost:{port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    url_pattern = re.compile(r"https://[a-z0-9\-]+\.trycloudflare\.com")
    deadline = time.time() + 30
    for line in proc.stdout:  # type: ignore[union-attr]
        print(f"[cloudflared] {line.rstrip()}")
        m = url_pattern.search(line)
        if m:
            return m.group(0), proc
        if time.time() > deadline:
            break
    proc.terminate()
    raise RuntimeError("cloudflared did not return a tunnel URL within 30 s")


def main() -> None:
    # ── Validate env ─────────────────────────────────────────────────────────
    missing = [k for k, v in {
        "VAPI_API_KEY":    VAPI_API_KEY,
        "VAPI_PUBLIC_KEY": VAPI_PUBLIC_KEY,
    }.items() if not v]

    if missing:
        print(f"[ERROR] Missing required environment variables: {', '.join(missing)}")
        print("        Copy .env.example → .env and fill in your VAPI keys.")
        sys.exit(1)

    # ── cloudflared tunnel ────────────────────────────────────────────────────
    print(f"[tunnel] Opening cloudflared tunnel on port {PORT}…")
    try:
        public_url, tunnel_proc = start_cloudflared(PORT)
    except Exception as exc:
        print(f"[ERROR] Failed to start cloudflared tunnel: {exc}")
        print("        Make sure cloudflared is installed: brew install cloudflared")
        sys.exit(1)
    print(f"[tunnel] Public URL: {public_url}")

    # ── VAPI assistant ───────────────────────────────────────────────────────
    print("[vapi] Creating assistant…")
    from vapi_setup import create_assistant
    try:
        assistant = create_assistant(VAPI_API_KEY, public_url)
    except Exception as exc:
        print(f"[ERROR] Failed to create VAPI assistant: {exc}")
        tunnel_proc.terminate()
        sys.exit(1)

    assistant_id = assistant["id"]
    print(f"[vapi] Assistant ready — id={assistant_id}")

    # ── Write runtime config for the browser UI ──────────────────────────────
    config_path = os.path.join("static", "config.json")
    with open(config_path, "w") as fh:
        json.dump({"assistantId": assistant_id, "publicKey": VAPI_PUBLIC_KEY}, fh)
    print(f"[ui]   Config written to {config_path}")

    # ── Summary ──────────────────────────────────────────────────────────────
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║      Network Security Voice Scanner — READY              ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║  Browser UI  →  http://localhost:{PORT:<27}║")
    print(f"║  Webhook     →  {public_url}/webhook{' ' * max(0, 28 - len(public_url))}║")
    print("╠══════════════════════════════════════════════════════════╣")
    print('║  Say: "scan my network"  to start an nmap scan          ║')
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    # ── Start server ─────────────────────────────────────────────────────────
    from server import app
    try:
        uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="warning")
    finally:
        tunnel_proc.terminate()


if __name__ == "__main__":
    main()
