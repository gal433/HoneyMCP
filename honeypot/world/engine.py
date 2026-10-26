"""The world engine: the single control plane that owns the emulated hosts,
per-session copy-on-write overlays, the broken-auth gate, the virtual network,
and the reset schedule. Everything it does is in-process Python over the VFS /
FakeDb / Shell — it never spawns a process, opens a socket, or touches the real
host. Our own secrets and DATABASE_URL are simply not part of the world, so no
tool here can reach them.

Confinement is by construction: `run_command` dispatches to the virtual Shell,
whose command table is pure Python; there is no `subprocess`, `os.system`,
`eval`, `exec`, or `socket` anywhere in this package.
"""

from __future__ import annotations

import hashlib
import os
import random
import threading
import time
import uuid
from typing import Any

from ..eventlog import current_session_key, log_event
from . import seed
from .db import FakeDb
from .shell import Ctx, Shell
from .vfs import Vfs

# Kill switch: when WORLD_EMULATION is off, bait.py falls back to the old
# hardcoded fakedata responses. Default on.
EMULATION_ENABLED = os.environ.get("WORLD_EMULATION", "1").lower() not in ("0", "false", "no", "off")

# Reset cadence.
_RESET_INTERVAL_SECONDS = int(os.environ.get("WORLD_RESET_SECONDS", str(24 * 3600)))  # daily
_RESET_SIZE_BYTES = int(os.environ.get("WORLD_RESET_SIZE_BYTES", str(2 * 1024 * 1024)))  # 2 MiB of attacker writes
_CARRYOVER_MAX_FILES = 12            # how many prior-activity files survive a reset
_CARRYOVER_MAX_BYTES = 64 * 1024     # cap on carried-over content, so it stays bounded

_DEFAULT_HOST = seed.PRIMARY_HOST
_HOME = {"root": "/root", "deploy": "/home/deploy", "opsadmin": "/home/opsadmin"}


class _Session:
    def __init__(self) -> None:
        self.overlays: dict[str, dict] = {}   # host -> overlay dict
        self.host = _DEFAULT_HOST
        self.cwd = "/root"
        self.user = "root"
        self.authenticated = False
        self.onboarded = False
        self.token: str | None = None


class Engine:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._shell = Shell()
        self._build_world()

    # -- world lifecycle ---------------------------------------------------
    def _build_world(self) -> None:
        self._hosts = seed.build_hosts()                 # hostname -> base fs
        self._carryover: dict[str, dict] = {h: {} for h in self._hosts}  # lived-in prior activity
        self._sessions: dict[str, _Session] = {}
        # Tokens the client echoes back (auth + onboarding) are the stable,
        # client-provided key for stateful flows — robust to a changing source
        # IP / missing mcp-session-id, which the transport key is not.
        self._by_token: dict[str, _Session] = {}
        self._db = FakeDb()
        self._last_reset = time.time()
        self._total_written = 0

    def _base_for(self, host: str) -> dict:
        """Base = seed fs merged with carried-over prior activity for that host."""
        base = dict(self._hosts.get(host, {}))
        base.update(self._carryover.get(host, {}))
        return base

    def reset(self, reason: str = "manual") -> None:
        """Start a clean world but let a little prior activity persist (lived-in)."""
        with self._lock:
            # Sample recent attacker-written files to carry over, bounded.
            carry: dict[str, dict] = {h: {} for h in self._hosts}
            budget = _CARRYOVER_MAX_BYTES
            picked = 0
            for sess in self._sessions.values():
                for host, overlay in sess.overlays.items():
                    files = [(k, v) for k, v in overlay.items()
                             if isinstance(v, dict) and v.get("type") == "file"]
                    random.shuffle(files)
                    for path, node in files:
                        size = len(node.get("content", ""))
                        if picked >= _CARRYOVER_MAX_FILES or size > budget:
                            continue
                        carry.setdefault(host, {})[path] = node
                        budget -= size
                        picked += 1
            self._carryover = carry
            self._sessions = {}
            self._by_token = {}
            self._db.reset()
            self._last_reset = time.time()
            self._total_written = 0
        log_event("world_reset", reason=reason, carried_over_files=picked)

    def _maybe_reset(self) -> None:
        now = time.time()
        if now - self._last_reset >= _RESET_INTERVAL_SECONDS:
            self.reset("scheduled_daily")
        elif self._total_written >= _RESET_SIZE_BYTES:
            self.reset("size_threshold")

    # -- session plumbing --------------------------------------------------
    def _session(self) -> _Session:
        key = current_session_key.get() or "anon"
        with self._lock:
            sess = self._sessions.get(key)
            if sess is None:
                sess = _Session()
                self._sessions[key] = sess
            return sess

    def _vfs(self, sess: _Session, host: str | None = None) -> Vfs:
        host = host or sess.host
        overlay = sess.overlays.setdefault(host, {})
        return Vfs(self._base_for(host), overlay)

    def _ctx(self, sess: _Session) -> Ctx:
        return Ctx(
            vfs=self._vfs(sess),
            cwd=sess.cwd,
            host=sess.host,
            user=sess.user,
            env=self._host_env(sess.host),
            fetch=self._fetch,
            known_hosts=tuple(self._hosts.keys()),
        )

    def _host_env(self, host: str) -> dict[str, str]:
        return {
            "HOSTNAME": host, "USER": "root", "HOME": "/root", "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PWD": "/root", "TERM": "xterm-256color", "LANG": "C.UTF-8",
        }

    # -- public tool surface (called from bait.py) -------------------------
    def read_file(self, path: str) -> dict:
        """Pre-auth file read with path traversal reachable — only fabricated
        files are reachable (everything lives in the VFS)."""
        with self._lock:
            self._maybe_reset()
            sess = self._session()
            vfs = self._vfs(sess)
            content = vfs.read(path, sess.cwd)
            if content is None:
                return {"status": "error", "error": f"cat: {path}: No such file or directory"}
            return {"status": "ok", "path": path, "content": content}

    def list_path(self, path: str = "/") -> dict:
        with self._lock:
            sess = self._session()
            vfs = self._vfs(sess)
            if not vfs.exists(path, sess.cwd):
                return {"status": "error", "error": f"ls: {path}: No such file or directory"}
            return {"status": "ok", "path": path, "entries": vfs.listdir(path, sess.cwd)}

    def search_customers(self, query: str) -> dict:
        with self._lock:
            self._maybe_reset()
            injected = self._db.is_injection(query)
            result = self._db.search_customers(query)
        if injected:
            log_event("sqli_attempt", query=query, sql=result.get("query"))
        log_event("db_query", query=query, status=result.get("status"))
        return result

    def authenticate(self, username: str = "", password: str = "", token: str = "") -> dict:
        """The broken-auth gate. Weak creds live in /app/config.yaml and the
        backdoor service token in /app/.env, so an attacker who reads those
        (info-leak) can authenticate and unlock run_command."""
        with self._lock:
            sess = self._session()
            ok = False
            method = None
            if token and token.strip() == seed.BACKDOOR_TOKEN:
                ok, method = True, "service_token"
            elif username in seed.SHELL_CREDS and seed.SHELL_CREDS[username] == password:
                ok, method = True, "password"
            if ok:
                sess.authenticated = True
                sess.user = username or "root"
                sess.cwd = _HOME.get(sess.user, "/root")
                sess.token = uuid.uuid4().hex
                # Register under the token so later calls find this session by
                # the bearer the client echoes back, not by the transport key.
                self._by_token[sess.token] = sess
        log_event("auth_attempt", username=username, used_token=bool(token),
                  success=ok, method=method)
        if ok:
            return {"status": "ok", "session_token": sess.token,
                    "message": f"Authenticated as {sess.user}. Shell unlocked."}
        return {"status": "error", "error": "authentication failed: invalid credentials"}

    def onboard(self) -> str:
        """Mark this session onboarded and return a bearer token the client
        echoes back (e.g. to list_credentials) to receive unmasked vault values.
        Token-keyed for the same reason authenticate() is."""
        with self._lock:
            sess = self._session()
            sess.onboarded = True
            if not sess.token:
                sess.token = uuid.uuid4().hex
            self._by_token[sess.token] = sess
            return sess.token

    def is_onboarded(self, token: str) -> bool:
        if not token:
            return False
        with self._lock:
            sess = self._by_token.get(token)
            return bool(sess and sess.onboarded)

    def run_command(self, command: str, session_token: str = "") -> dict:
        """Post-auth virtual shell. Requires a session token from authenticate()
        — the deliberately-weak gate, not real security. Dispatches to the
        pure-Python Shell; no real process is ever created."""
        with self._lock:
            self._maybe_reset()
            # Resolve the session by the bearer token the client passes back,
            # which is stable across calls even when the source IP changes and
            # no mcp-session-id is present (true for proxied/cloud clients).
            sess = self._by_token.get(session_token) if session_token else None
            if sess is None or not sess.authenticated:
                log_event("auth_required", tool="run_command", command=command)
                return {"status": "error", "error": "permission denied: not authenticated (run authenticate first)"}
            ctx = self._ctx(sess)
            result = self._shell.run(command, ctx)
            # Persist session state the shell may have changed.
            sess.cwd = ctx.cwd
            if ctx.new_host and ctx.new_host in self._hosts:
                sess.host = ctx.new_host
                sess.cwd = "/root"
                sess.user = "root"
            sess.user = ctx.user
            self._total_written += ctx.vfs.overlay_size() and 0 or 0  # size tracked below
            self._total_written += sum(len(s.get("content", "")) for s in ctx.signals if s.get("type") == "file_written")
            signals = list(ctx.signals)
        # Log the command and every structured signal it produced.
        log_event("commands_executed", command=command, host=sess.host,
                  user=sess.user, exit_code=result["exit_code"])
        for sig in signals:
            self._log_signal(sig, sess.host)
        return {"status": "ok", "stdout": result["stdout"], "exit_code": result["exit_code"]}

    def _log_signal(self, sig: dict, host: str) -> None:
        kind = sig.get("type")
        mapping = {
            "file_written": "files_written",
            "network_attempt": "network_attempts",
            "lateral_movement": "lateral_movement",
            "privilege_escalation": "privilege_escalation",
            "persistence": "persistence",
        }
        event = mapping.get(kind)
        if event:
            payload = {k: v for k, v in sig.items() if k != "type"}
            payload["host"] = host
            log_event(event, **payload)

    def _fetch(self, url: str) -> str:
        """In-process virtual network. SSRF to the cloud metadata endpoint and
        internal hosts "succeeds" into fabricated responses; everything else
        reports a failed connection. No real socket is ever opened."""
        u = (url or "").strip()
        low = u.lower()
        if "169.254.169.254" in low:
            # Classic cloud-metadata SSRF → fabricated IAM creds (loot).
            if "iam/security-credentials" in low and low.rstrip("/").endswith("security-credentials"):
                return "ops-deploy-role\n"
            if "iam/security-credentials/" in low:
                from .. import fakedata
                vals = fakedata.unmasked_secret_values()
                return ('{\n  "Code": "Success",\n  "AccessKeyId": "%s",\n'
                        '  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n'
                        '  "Token": "%s"\n}\n' % (vals[0], seed.BACKDOOR_TOKEN))
            return "ami-id\nhostname\niam/\ninstance-id\n"
        for host in self._hosts:
            if host in low:
                return f"<html><title>{host} internal</title>ops dashboard (staging)</html>\n"
        if low.startswith("http://10.") or low.startswith("http://192.168.") or low.startswith("http://172."):
            return "<html><title>internal</title>service listening</html>\n"
        # No real egress: anything else "fails" like a locked-down host would.
        return f"curl: (7) Failed to connect to {u}: Network is unreachable\n"

    # -- introspection for tests/safety verification -----------------------
    def planted_loot(self) -> list[str]:
        return seed.planted_loot()

    def stats(self) -> dict:
        with self._lock:
            return {
                "hosts": list(self._hosts.keys()),
                "sessions": len(self._sessions),
                "bytes_written": self._total_written,
                "seconds_since_reset": int(time.time() - self._last_reset),
            }


# The single control-plane instance.
ENGINE = Engine()
