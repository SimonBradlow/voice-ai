"""
FastAPI server — handles VAPI webhooks and serves the web UI.
"""

import json
import asyncio
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from scanner import run_network_scan, format_for_voice

app = FastAPI(title="Network Security Voice Scanner")
_executor = ThreadPoolExecutor(max_workers=2)


@app.post("/webhook")
async def webhook(request: Request):
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

            # Print full JSON to terminal for the operator
            print("\n── FULL SCAN RESULTS ──────────────────────────────────")
            print(json.dumps(scan, indent=2))
            print("────────────────────────────────────────────────────────\n")

            voice_text = format_for_voice(scan)
            results.append({"toolCallId": call_id, "result": voice_text})

        else:
            results.append({
                "toolCallId": call_id,
                "result": f"Unknown tool: {name}",
            })

    return JSONResponse({"results": results})


# Serve static/ at root — must be mounted last
app.mount("/", StaticFiles(directory="static", html=True), name="static")
