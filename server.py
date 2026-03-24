"""
FastAPI server — handles VAPI webhooks and serves the web UI.
"""

import json
import asyncio
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from scanner import run_network_scan, format_for_voice
from pdf_report import generate_pdf

app = FastAPI(title="Network Security Voice Scanner")
_executor = ThreadPoolExecutor(max_workers=2)

# In-memory stores for the most recent scan and generated PDF.
# Single-user app — we only ever keep the latest result.
_latest_scan: dict | None = None
_latest_pdf: bytes | None = None


@app.post("/webhook")
async def webhook(request: Request):
    global _latest_scan, _latest_pdf

    body = await request.json()
    print(f"\n[webhook] RAW BODY: {json.dumps(body, indent=2)}")
    message = body.get("message", {})

    if message.get("type") != "tool-calls":
        return JSONResponse({"status": "ok"})

    loop = asyncio.get_event_loop()
    results = []

    for tool_call in message.get("toolCallList", []):
        call_id = tool_call.get("id")
        fn      = tool_call.get("function", {})
        name    = fn.get("name")
        args    = fn.get("arguments", {})
        params  = args if isinstance(args, dict) else json.loads(args or "{}")

        if name == "runNetworkScan":
            target = params.get("target") or None

            print(f"\n[webhook] runNetworkScan called — target={target or 'auto'}")

            # Run blocking nmap in a thread so we don't block the event loop
            scan = await loop.run_in_executor(
                _executor,
                lambda t=target: run_network_scan(t),
            )

            # Persist results for potential PDF export
            _latest_scan = scan
            _latest_pdf = None  # clear any stale PDF

            # Print full JSON to terminal for the operator
            print("\n── FULL SCAN RESULTS ──────────────────────────────────")
            print(json.dumps(scan, indent=2))
            print("────────────────────────────────────────────────────────\n")

            voice_text = format_for_voice(scan)
            results.append({"toolCallId": call_id, "result": voice_text})

        elif name == "generateReport":
            if _latest_scan is None:
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
                    lambda: generate_pdf(_latest_scan),
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
            results.append({
                "toolCallId": call_id,
                "result": f"Unknown tool: {name}",
            })

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
