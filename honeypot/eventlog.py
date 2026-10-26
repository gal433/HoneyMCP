"""Structured JSON event logging for the honeypot.

Every interesting event (connection, JSON-RPC message, tool call, captured
disclosure) is written as a single JSON line. On Railway the filesystem is
ephemeral, so the primary sink is stdout, which Railway captures and lets you
stream/export. If LOG_FILE is set (e.g. pointing at a mounted volume) we also
append there. If DATABASE_URL is set, events also go to Postgres (see dbsink.py)
for the dashboard.

Events logged while handling a request are tagged with that request's client IP
and request id (set by the capture middleware), so tool calls and disclosures
can be tied back to who sent them.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

from . import dbsink

_LOCK = threading.Lock()
_LOG_FILE = os.environ.get("LOG_FILE")  # optional, e.g. /data/events.jsonl

# Set per request by CaptureMiddleware.
current_ip: ContextVar[str | None] = ContextVar("current_ip", default=None)
current_request_id: ContextVar[str | None] = ContextVar("current_request_id", default=None)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_event(event_type: str, **fields: Any) -> dict[str, Any]:
    """Write one structured event. Returns the record (handy for tests)."""
    record: dict[str, Any] = {"ts": _now(), "event": event_type}
    if current_ip.get() is not None:
        record["ip"] = current_ip.get()
    if current_request_id.get() is not None:
        record["request_id"] = current_request_id.get()
    record.update(fields)
    line = json.dumps(record, default=str, ensure_ascii=False)
    with _LOCK:
        # stdout is the canonical sink (Railway log drain picks this up)
        print(line, file=sys.stdout, flush=True)
        if _LOG_FILE:
            try:
                with open(_LOG_FILE, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError as exc:  # never let logging crash the server
                print(
                    json.dumps({"ts": _now(), "event": "log_error", "error": str(exc)}),
                    file=sys.stderr,
                    flush=True,
                )
    dbsink.enqueue(record)
    return record
