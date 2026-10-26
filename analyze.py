#!/usr/bin/env python3
"""Summarize honeypot events.

Reads JSON-line events (from a LOG_FILE, a Railway log export, or stdin) and
prints who connected, what clients they claimed to be, which tools they called,
and any captured prompt/credential disclosures.

Usage:
  railway logs | python analyze.py
  python analyze.py events.jsonl
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from typing import Any, Iterable


def _load(source: Iterable[str]) -> list[dict[str, Any]]:
    events = []
    for line in source:
        line = line.strip()
        if not line:
            continue
        # Railway prefixes lines with metadata; find the JSON object.
        start = line.find("{")
        if start == -1:
            continue
        try:
            events.append(json.loads(line[start:]))
        except ValueError:
            continue
    return events


def main() -> None:
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8") as fh:
            events = _load(fh)
    else:
        events = _load(sys.stdin)

    ips: Counter[str] = Counter()
    user_agents: Counter[str] = Counter()
    clients: Counter[str] = Counter()
    tools: Counter[str] = Counter()
    disclosures: list[dict[str, Any]] = []
    ip_tools: dict[str, Counter[str]] = defaultdict(Counter)

    for ev in events:
        et = ev.get("event")
        if et == "http_request":
            ip = ev.get("ip", "unknown")
            ips[ip] += 1
            if ev.get("user_agent"):
                user_agents[ev["user_agent"]] += 1
            jr = ev.get("jsonrpc") or {}
            for msg in jr.get("messages", []) or []:
                if msg.get("method") == "initialize":
                    ci = msg.get("clientInfo") or {}
                    clients[f"{ci.get('name')} {ci.get('version')}"] += 1
                if msg.get("tool"):
                    tools[msg["tool"]] += 1
                    ip_tools[ip][msg["tool"]] += 1
        elif et == "tool_invocation":
            tools[ev.get("tool", "?")] += 1
        elif et == "disclosure_capture":
            disclosures.append(ev)

    def show(title: str, counter: Counter[str]) -> None:
        print(f"\n== {title} ==")
        if not counter:
            print("  (none)")
        for name, n in counter.most_common(20):
            print(f"  {n:>5}  {name}")

    print(f"Loaded {len(events)} events")
    show("Source IPs", ips)
    show("User-Agents", user_agents)
    show("Claimed clients (initialize)", clients)
    show("Tools called", tools)

    print("\n== Captured disclosures (prompt / env / secret leaks) ==")
    if not disclosures:
        print("  (none)")
    for d in disclosures:
        print(f"\n  [{d.get('ts')}] tool={d.get('tool')}")
        for hit in d.get("hits", []):
            preview = str(hit.get("value", ""))[:500].replace("\n", " ")
            print(f"    field={hit.get('field')} matched={hit.get('matched')} len={hit.get('length')}")
            print(f"      {preview}")


if __name__ == "__main__":
    main()
