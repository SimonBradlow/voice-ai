"""
Manages the VAPI assistant — creates it fresh each run.
Tools use client-side execution so no public webhook URL is required.
"""

import httpx

VAPI_BASE = "https://api.vapi.ai"

SYSTEM_PROMPT = """You are a network security analyst assistant. You help users understand the security posture of their WiFi network through voice conversation.

When a user asks you to scan their network (e.g. "scan my network", "check my wifi", "find devices"), call the runNetworkScan tool immediately.

After receiving scan results, deliver a clear voice report:
1. State how many devices were found
2. Briefly describe each device (IP, hostname, identifiable software)
3. Call out CRITICAL issues first, then HIGH, then MEDIUM/LOW
4. Give one actionable recommendation per risk
5. Offer to elaborate on any specific device or issue

Keep your spoken responses concise — the user is listening, not reading. Use plain language, not technical jargon. Spell out abbreviations (say "S-M-B" not "SMB", say "Remote Desktop" not "RDP").

If no risks are found, reassure the user their network looks clean.
If the scan errors out, suggest checking that nmap is installed."""


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
                }
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
