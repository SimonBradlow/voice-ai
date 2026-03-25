"""
FastAPI server — handles VAPI webhooks and serves the web UI.
"""

import json
import asyncio
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from scanner import run_network_scan, run_vuln_scan, format_for_voice, format_vuln_for_voice
from pdf_report import generate_pdf

app       = FastAPI(title="Network Security Voice Scanner")
_executor = ThreadPoolExecutor(max_workers=2)

# In-memory stores for the most recent scan and generated PDF.
# Single-user app — we only ever keep the latest result.
_last_scan:   dict  | None = None
_latest_pdf:  bytes | None = None


@app.get("/api/devices")
async def get_devices():
    if _last_scan is None:
        return JSONResponse({"devices": [], "scanned": False})
    return JSONResponse({
        "scanned":  True,
        "network":  _last_scan.get("network", ""),
        "devices":  _last_scan.get("devices", []),
    })


@app.post("/webhook")
async def webhook(request: Request):
    global _last_scan, _latest_pdf

    body    = await request.json()
    message = body.get("message", {})

    if message.get("type") != "tool-calls":
        return JSONResponse({"status": "ok"})

    loop    = asyncio.get_event_loop()
    results = []

    for tool_call in message.get("toolCallList", []):
        call_id = tool_call.get("id")
        fn      = tool_call.get("function", {})
        name    = fn.get("name")
        args    = fn.get("arguments", {})
        params  = args if isinstance(args, dict) else json.loads(args or "{}")

        if name == "runNetworkScan":
            target = params.get("target") or None
            print(f"\n[webhook] runNetworkScan — target={target or 'auto'}")

            scan = await loop.run_in_executor(
                _executor, lambda t=target: run_network_scan(t)
            )
            _last_scan  = scan
            _latest_pdf = None  # clear any stale PDF

            print("\n── SCAN RESULTS ────────────────────────────────────────")
            print(json.dumps(scan, indent=2))
            print("────────────────────────────────────────────────────────\n")

            results.append({"toolCallId": call_id, "result": format_for_voice(scan)})

        elif name == "runVulnScan":
            ip = params.get("ip", "").strip()
            if not ip:
                results.append({"toolCallId": call_id, "result": "No IP address provided."})
                continue

            print(f"\n[webhook] runVulnScan — ip={ip}")
            vuln = await loop.run_in_executor(
                _executor, lambda i=ip: run_vuln_scan(i)
            )

            print("\n── VULN SCAN RESULTS ───────────────────────────────────")
            print(json.dumps(vuln, indent=2))
            print("────────────────────────────────────────────────────────\n")

            results.append({"toolCallId": call_id, "result": format_vuln_for_voice(vuln)})

        elif name == "generateReport":
            if _last_scan is None:
                results.append({
                    "toolCallId": call_id,
                    "result": (
                        "There are no scan results available yet. "
                        "Please run a network scan first, then I can generate a report."
                    ),
                })
            else:
                print("\n[webhook] generateReport called — building PDF…")
                _latest_pdf = await loop.run_in_executor(
                    _executor,
                    lambda: generate_pdf(_last_scan),
                )
                print(f"[webhook] PDF generated — {len(_latest_pdf):,} bytes")
                results.append({
                    "toolCallId": call_id,
                    "result": (
                        "Your PDF report is ready. "
                        "It's downloading to your browser right now."
                    ),
                })

        else:
            results.append({"toolCallId": call_id, "result": f"Unknown tool: {name}"})

    return JSONResponse({"results": results})


@app.get("/api/download-pdf")
async def download_pdf():
    """Return the most recently generated PDF report as a file download."""
    if _latest_pdf is None:
        return JSONResponse({"error": "No PDF report available yet."}, status_code=404)
    return Response(
        content=_latest_pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="network-security-report.pdf"'},
    )


# Serve static/ at root — must be mounted last
app.mount("/", StaticFiles(directory="static", html=True), name="static")
