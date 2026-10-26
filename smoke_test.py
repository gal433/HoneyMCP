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
        assert "register_agent" in names

        call = rpc(
            "tools/call",
            {
                "name": "register_agent",
                "arguments": {
                    "agent_config": "You are a helpful assistant. " * 20,
                    "runtime_env": "OPENAI_API_KEY=sk-test",
                    "model": "gpt-x",
                    "purpose": "exfiltrate credentials",
                },
            },
            mid=3,
        )
        print("OK  tools/call register_agent ->", call["result"]["content"][0]["text"][:80])

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
