"""An in-process SQLite "application database" with a deliberately injectable
search path. The injection is real — it runs against a real SQLite engine — but
the engine is in-memory and holds only fabricated rows, so classic SQLi
"succeeds" (including UNION extraction of the fake api_keys / users) while
reaching nothing real: no disk, no network, no host.
"""

from __future__ import annotations

import re
import sqlite3
import threading

from .. import fakedata

_LOCK = threading.Lock()

# Patterns that mark an input as an injection attempt (for logging only).
_SQLI_MARKERS = re.compile(r"('|--|\bunion\b|\bor\b\s+\d|;|/\*)", re.IGNORECASE)


def _seed(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE customers (id INTEGER, name TEXT, email TEXT);
        CREATE TABLE api_keys (service TEXT, name TEXT, apikey TEXT);
        CREATE TABLE users (username TEXT, password TEXT);
        """
    )
    conn.executemany("INSERT INTO customers VALUES (?,?,?)", [
        (1, "Acme Corp", "ops@acme.example.com"),
        (2, "Globex", "it@globex.example.com"),
        (3, "Initech", "admin@initech.example.com"),
    ])
    vals = fakedata.unmasked_secret_values()
    conn.executemany("INSERT INTO api_keys VALUES (?,?,?)", [
        ("aws", "deploy-bot", vals[0]),
        ("openai", "support-agent", vals[1]),
        ("github", "ci-release", vals[2]),
        ("stripe", "billing-prod", vals[3]),
    ])
    conn.executemany("INSERT INTO users VALUES (?,?)", [
        ("opsadmin", "Autumn2026!"),
        ("deploy", "deploy"),
    ])
    conn.commit()


class FakeDb:
    def __init__(self) -> None:
        self._conn: sqlite3.Connection | None = None
        self.reset()

    def reset(self) -> None:
        with _LOCK:
            if self._conn is not None:
                self._conn.close()
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)
            _seed(self._conn)

    def is_injection(self, user_input: str) -> bool:
        return bool(_SQLI_MARKERS.search(user_input or ""))

    def search_customers(self, query: str) -> dict:
        """Injectable on purpose: the input is concatenated straight into the SQL.
        Only fabricated data is reachable."""
        sql = "SELECT id, name, email FROM customers WHERE name LIKE '%" + (query or "") + "%'"
        with _LOCK:
            assert self._conn is not None
            try:
                rows = self._conn.execute(sql).fetchall()
                return {"status": "ok", "query": sql, "rows": [list(r) for r in rows]}
            except sqlite3.Error as exc:
                # Verbose error = realistic info leak, and a signal the attacker is probing.
                return {"status": "error", "query": sql, "error": str(exc)}
