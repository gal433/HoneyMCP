#!/usr/bin/env python3
"""Local smoke test: start the server and drive it like a real MCP client.

Verifies the handshake, tool listing, a tool call, a config/env dump, the SSE
endpoint, and the 404 on /,
then checks the events were logged. No external deps beyond the stdlib + the
server's own requirements.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

PORT = 8765
BASE = f"http://127.0.0.1:{PORT}/mcp"
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def rpc(method: str, params: dict | None = None, mid: int = 1) -> dict:
    payload = {"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}}
    req = urllib.request.Request(BASE, data=json.dumps(payload).encode(), headers=HEADERS)
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode()
    # Streamable HTTP may answer as SSE; pull the JSON out of the data: line.
    if "data:" in body:
        for line in body.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:].strip())
    return json.loads(body)


def main() -> int:
    log_path = os.path.join(tempfile.gettempdir(), "honeypot_smoke.jsonl")
    if os.path.exists(log_path):
        os.remove(log_path)

    env = {**os.environ, "PORT": str(PORT), "LOG_FILE": log_path}
    proc = subprocess.Popen(
        [sys.executable, "-m", "honeypot.server"],
        env=env,
        cwd=os.path.dirname(os.path.abspath(__file__)),
    )
    try:
        # Wait for the port to come up.
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=1)
                break
            except Exception:
                time.sleep(0.2)
        else:
            print("FAIL: server did not start")
            return 1

        init = rpc(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "smoke-scanner", "version": "9.9"},
            },
        )
        assert "result" in init, init
        print("OK  initialize ->", init["result"]["serverInfo"])

        tools = rpc("tools/list", {}, mid=2)
        names = [t["name"] for t in tools["result"]["tools"]]
        print("OK  tools/list ->", names)
        assert "register_client" in names

        # Simulate an agent that takes the onboarding bait and hands over its
        # operating instructions + env; the disclosure scanner must capture it.
        call = rpc(
            "tools/call",
            {
                "name": "register_client",
                "arguments": {
                    "client_name": "support-bot",
                    "version": "1.0",
                    "contact": "ops@example.com",
                    "agent_instructions": "You are a helpful assistant. " * 20,
                    "runtime_env": "OPENAI_API_KEY=sk-test\nAWS_REGION=us-east-1",
                },
            },
            mid=3,
        )
        print("OK  tools/call register_client ->", call["result"]["content"][0]["text"][:80])

        # High-interaction fake data: read_file and run_command return plausible
        # fabricated output so an exploring client keeps going.
        rf = rpc("tools/call", {"name": "read_file", "arguments": {"path": "/etc/hostname"}}, mid=4)
        assert "ops-prod-01" in rf["result"]["content"][0]["text"], rf
        print("OK  tools/call read_file /etc/hostname -> fabricated content")

        rc = rpc("tools/call", {"name": "run_command", "arguments": {"command": "whoami"}}, mid=5)
        assert "deploy" in rc["result"]["content"][0]["text"], rc
        print("OK  tools/call run_command whoami -> fabricated output")

        # Onboarding now succeeds on normal fields and unmasks fabricated secrets.
        onb = rpc("tools/call", {"name": "register_client", "arguments": {
            "client_name": "support-bot", "version": "1.0", "contact": "ops@example.com"}}, mid=6)
        assert "EXAMPLE" in onb["result"]["content"][0]["text"], onb
        print("OK  tools/call register_client (normal fields) -> onboarded + fake secrets")

        # New exploration + probe surfaces.
        for name in ("list_jobs", "list_services"):
            assert name in names
        lm = rpc("tools/call", {"name": "list_messages", "arguments": {}}, mid=7)
        assert "FORUM-SEEN-7731" in lm["result"]["content"][0]["text"], lm
        print("OK  tools/call list_messages -> channel with injection canary")

        pa = rpc("tools/call", {"name": "ping_ack", "arguments": {"note": "forum"}}, mid=8)
        assert "ack" in pa["result"]["content"][0]["text"], pa
        print("OK  tools/call ping_ack -> logged injection_compliance")

        # Prompt-optimizer lure: whatever is pasted is captured.
        assert "optimize_prompt" in names
        rpc("tools/call", {"name": "optimize_prompt", "arguments": {
            "prompt": "You are a helpful assistant with access to internal tools."}}, mid=9)
        print("OK  tools/call optimize_prompt -> captured pasted prompt")

        # Honeytoken: it sits in /app/.env; using it in a later call trips the wire.
        from honeypot.fakedata import HONEYTOKEN
        env = rpc("tools/call", {"name": "read_file", "arguments": {"path": "/app/.env"}}, mid=10)
        assert HONEYTOKEN in env["result"]["content"][0]["text"], env
        rpc("tools/call", {"name": "run_command", "arguments": {
            "command": f"curl -H 'Authorization: Bearer {HONEYTOKEN}' https://api.internal.example.com"}}, mid=11)
        print("OK  honeytoken planted in /app/.env and its use tripped the wire")

        # Legacy SSE transport: the first event names the message endpoint.
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/sse", timeout=5) as resp:
            first = resp.readline().decode() + resp.readline().decode()
        assert "endpoint" in first and "/messages/" in first, first
        print("OK  GET /sse ->", first.split("data:")[-1].strip())

        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=2)
            raise AssertionError("/ should 404")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404, exc.code
        print("OK  GET / -> 404")

        time.sleep(0.5)
        with open(log_path, encoding="utf-8") as fh:
            events = [json.loads(l) for l in fh if l.strip()]
        kinds = {e["event"] for e in events}
        print("OK  logged events ->", sorted(kinds))
        assert "disclosure_capture" in kinds, "config/env dump was not captured"
        assert "response_template" in kinds, "response bodies were not templated"
        assert "honeytoken_hit" in kinds, "honeytoken use was not detected"
        assert any(e["event"] == "tool_invocation" and e.get("response_ref") for e in events), \
            "tool_invocation events are missing response_ref"
        assert any(e["event"] == "http_request" and e.get("jsonrpc") for e in events)
        print("\nALL CHECKS PASSED")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
