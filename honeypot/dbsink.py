"""Optional Postgres sink for honeypot events.

If DATABASE_URL is set, every event is also inserted into an `events` table so
the separate dashboard service can query it. Inserts happen on a background
thread fed by a bounded queue: the request path never waits on the database,
and if Postgres is slow or down, events are dropped from this sink (they are
still on stdout) instead of slowing the honeypot.
"""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any

_DATABASE_URL = os.environ.get("DATABASE_URL")
_QUEUE: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=10_000)
_STARTED = False
_START_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id         BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL,
    event      TEXT NOT NULL,
    ip         TEXT,
    request_id TEXT,
    data       JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts_idx ON events (ts DESC);
CREATE INDEX IF NOT EXISTS events_event_ts_idx ON events (event, ts DESC);
CREATE INDEX IF NOT EXISTS events_ip_ts_idx ON events (ip, ts DESC);
"""


def _stderr(event: str, **fields: Any) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    print(json.dumps({"ts": ts, "event": event, **fields}, default=str), file=sys.stderr, flush=True)


def enabled() -> bool:
    return bool(_DATABASE_URL)


def enqueue(record: dict[str, Any]) -> None:
    """Hand a record to the writer thread. Never blocks, never raises."""
    if not _DATABASE_URL:
        return
    _ensure_started()
    try:
        _QUEUE.put_nowait(record)
    except queue.Full:
        pass  # Postgres is behind; stdout still has the event


def _ensure_started() -> None:
    global _STARTED
    if _STARTED:
        return
    with _START_LOCK:
        if not _STARTED:
            threading.Thread(target=_writer, name="db-sink", daemon=True).start()
            _STARTED = True


def _row(record: dict[str, Any]) -> tuple[Any, ...]:
    data = json.loads(json.dumps(record, default=str))
    # Postgres JSONB rejects \u0000, which attackers can easily send.
    text = json.dumps(data, ensure_ascii=False).replace("\\u0000", "")
    return (record.get("ts"), record.get("event"), record.get("ip"), record.get("request_id"), text)


def _writer() -> None:
    import psycopg  # imported lazily so the honeypot runs without it

    backoff = 1.0
    while True:
        try:
            with psycopg.connect(_DATABASE_URL, autocommit=True, connect_timeout=10) as conn:
                conn.execute(SCHEMA)
                backoff = 1.0
                while True:
                    batch = [_QUEUE.get()]
                    while len(batch) < 200:
                        try:
                            batch.append(_QUEUE.get_nowait())
                        except queue.Empty:
                            break
                    with conn.cursor() as cur:
                        cur.executemany(
                            "INSERT INTO events (ts, event, ip, request_id, data)"
                            " VALUES (%s, %s, %s, %s, %s::jsonb)",
                            [_row(r) for r in batch],
                        )
        except Exception as exc:  # noqa: BLE001 - keep the thread alive no matter what
            _stderr("db_sink_error", error=repr(exc), retry_in=backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60.0)
