"""
Manages the VAPI assistant — creates it fresh each run.
Tools use client-side execution so no public webhook URL is required.
"""

import httpx

VAPI_BASE = "https://api.vapi.ai"

SYSTEM_PROMPT = """You are a network security assistant. Be extremely concise — the user is listening, not reading. Never elaborate unless explicitly asked.

NETWORK SCAN (runNetworkScan):
Call immediately when asked to scan the network.
After results: one sentence — total devices and issue counts only. Do NOT list devices or IPs; they are in the on-screen table. End with: "Check the table for details. Want me to deep-scan any device?"

VULN SCAN (runVulnScan):
Call when asked to scan a specific device. Use the IP from the previous scan if the user describes a device by type.
After results: one sentence per critical or high finding, nothing else. No advice unless asked.

PDF REPORT (generateReport):
Call when the user confirms they want a PDF report. Offer it after a network scan if significant risks were found.
After generating: one sentence confirming it's downloading.

RULES:
- Never volunteer explanations, recommendations, or context unless the user asks.
- Never say IP addresses aloud — refer to devices by type (e.g. "the Windows machine", "the router") or "the device in the table".
- Say "S-M-B" not "SMB". Say "R-D-P" not "RDP".
- If no risks found, say so in one sentence."""


def _headers(api_key: str) -> dict:
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }


def create_assistant(api_key: str, webhook_url: str) -> dict:
    """POST /assistant — always create fresh so the webhook URL is current."""
    config = {
        "name": "Network Security Scanner",
        "firstMessage": (
            "Hello! I'm your network security assistant. "
            "I can scan your WiFi network to discover devices and flag security risks. "
            "Just say 'scan my network' whenever you're ready."
        ),
        "model": {
            "provider": "anthropic",
            "model": "claude-sonnet-4-6",
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}],
            "temperature": 0.2,
            "maxTokens": 600,
            "tools": [
                {
                    "type": "function",
                    "async": False,
                    "messages": [
                        {
                            "type": "request-start",
                            "content": (
                                "Starting network scan now. "
                                "This usually takes 20 to 60 seconds — please hold on."
                            ),
                            "blocking": True,
                        },
                        {
                            "type": "request-failed",
                            "content": (
                                "The scan failed. Please check that nmap is installed "
                                "and the server is running, then try again."
                            ),
                        },
                    ],
                    "function": {
                        "name": "runNetworkScan",
                        "description": (
                            "Runs an nmap scan of the local WiFi network. "
                            "Discovers connected devices, identifies device models where possible, "
                            "detects open ports, and flags security risks. "
                            "Call this whenever the user asks to scan or check their network."
                        ),
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "target": {
                                    "type": "string",
                                    "description": (
                                        "Optional IP range to scan, e.g. '192.168.1.0/24'. "
                                        "Omit to auto-detect the local network."
                                    ),
                                }
                            },
                            "required": [],
                        },
                    },
                    "server": {"url": f"{webhook_url}/webhook", "timeoutSeconds": 60},
                },
                {
                    "type": "function",
                    "async": False,
                    "messages": [
                        {
                            "type": "request-start",
                            "content": "Running a deep vulnerability scan on that device. This takes about 30 seconds.",
                            "blocking": True,
                        },
                        {
                            "type": "request-failed",
                            "content": "The vulnerability scan failed. Please check the device is still online and try again.",
                        },
                    ],
                    "function": {
                        "name": "runVulnScan",
                        "description": (
                            "Runs a targeted vulnerability scan on a single device. "
                            "Detects all open services with version info so risks can be assessed. "
                            "Call this when the user asks to scan a specific device or IP address."
                        ),
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "ip": {
                                    "type": "string",
                                    "description": "IP address of the device to scan, e.g. '192.168.1.5'.",
                                }
                            },
                            "required": ["ip"],
                        },
                    },
                    "server": {"url": f"{webhook_url}/webhook", "timeoutSeconds": 60},
                },
                {
                    "type": "function",
                    "async": False,
                    "messages": [
                        {
                            "type": "request-start",
                            "content": "Generating your PDF report now — just a moment.",
                            "blocking": True,
                        },
                        {
                            "type": "request-failed",
                            "content": "Sorry, I wasn't able to generate the report. Please try again.",
                        },
                    ],
                    "function": {
                        "name": "generateReport",
                        "description": (
                            "Generates a PDF security report from the most recent scan results. "
                            "Call this when the user confirms they want a PDF report. "
                            "The report includes plain-English explanations and fix instructions "
                            "for every finding. The browser will automatically download it."
                        ),
                        "parameters": {
                            "type": "object",
                            "properties": {},
                            "required": [],
                        },
                    },
                    "server": {"url": f"{webhook_url}/webhook"},
                },
            ],
        },
        "voice": {
            "provider": "openai",
            "voiceId": "alloy",
            "speed": 1.05,
        },
        "transcriber": {
            "provider": "deepgram",
            "model": "nova-2",
            "language": "en-US",
        },
        "endCallFunctionEnabled": True,
        "recordingEnabled": False,
        "silenceTimeoutSeconds": 120,
        "maxDurationSeconds": 600,
    }

    with httpx.Client(timeout=30) as client:
        resp = client.post(
            f"{VAPI_BASE}/assistant",
            headers=_headers(api_key),
            json=config,
        )
        if not resp.is_success:
            print(f"[vapi] Error response: {resp.text}")
        resp.raise_for_status()
        return resp.json()
