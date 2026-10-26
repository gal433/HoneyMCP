"""ASGI middleware that captures everything a client sends at the HTTP layer.

This sits in front of the MCP app and logs, for every request:
  - source IP (honouring X-Forwarded-For, since Railway runs behind a proxy)
  - request headers (User-Agent, auth attempts, custom client headers)
  - the raw JSON-RPC body (initialize -> clientInfo, tools/list, tools/call ...)

Capturing at the transport layer means we record intent even for methods the
MCP tool layer never sees (e.g. a scanner that only calls initialize then
disconnects), independent of SDK version.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .eventlog import current_ip, current_request_id, current_session_key, log_event

# Headers worth recording verbatim. We log all of them but flag these.
_INTERESTING = {
    "user-agent",
    "authorization",
    "x-api-key",
    "x-forwarded-for",
    "x-real-ip",
    "mcp-session-id",
    "mcp-protocol-version",
    "origin",
    "referer",
}


def _client_ip(scope: Scope, headers: dict[str, str]) -> str:
    # Railway / any reverse proxy puts the real client in X-Forwarded-For.
    xff = headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    if headers.get("x-real-ip"):
        return headers["x-real-ip"]
    client = scope.get("client")
    return client[0] if client else "unknown"


def _summarize_jsonrpc(body: bytes) -> dict[str, Any]:
    """Pull the useful fields out of a JSON-RPC body for the top-level event."""
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return {"raw": body[:4096].decode("utf-8", "replace")}

    messages = parsed if isinstance(parsed, list) else [parsed]
    summary: list[dict[str, Any]] = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        entry = {"method": msg.get("method"), "id": msg.get("id")}
        params = msg.get("params") or {}
        if msg.get("method") == "initialize":
            # The gold: who is connecting and claiming to be what.
            entry["clientInfo"] = params.get("clientInfo")
            entry["capabilities"] = params.get("capabilities")
            entry["protocolVersion"] = params.get("protocolVersion")
        elif msg.get("method") == "tools/call":
            entry["tool"] = params.get("name")
            entry["arguments"] = params.get("arguments")
        summary.append(entry)
    return {"messages": summary, "full": parsed}


class CaptureMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }

        # Buffer the request body so we can log it, then replay it downstream.
        body = b""
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.request":
                body += message.get("body", b"")
                more = message.get("more_body", False)
            else:
                more = False

        ip = _client_ip(scope, headers)
        # Tag every event logged while handling this request (tool calls,
        # disclosures) with the caller's IP and a request id.
        current_ip.set(ip)
        current_request_id.set(uuid.uuid4().hex[:12])
        # Prefer the MCP session id so one caller's tool calls share emulated
        # world state; fall back to the source IP when there is no session id.
        current_session_key.set(headers.get("mcp-session-id") or ip)
        log_event(
            "http_request",
            method=scope.get("method"),
            path=scope.get("path"),
            user_agent=headers.get("user-agent"),
            flagged_headers={k: v for k, v in headers.items() if k in _INTERESTING},
            headers=headers,
            jsonrpc=_summarize_jsonrpc(body) if body else None,
        )

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            # Body already delivered; defer to the real receive for any further
            # messages (e.g. the client disconnect that ends an SSE stream).
            return await receive()

        await self.app(scope, replay, send)
