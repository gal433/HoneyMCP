"""A virtual filesystem: a shared read-only base plus a per-session copy-on-write
overlay. Nothing here touches the real host filesystem — every path, read, and
write lives entirely in Python dicts.

A node is a dict: {"type": "file"|"dir", "content": str, "mode": str, "owner":
str, "mtime": str}. Paths are absolute, normalized POSIX strings.
"""

from __future__ import annotations

import posixpath
from typing import Any

_TOMBSTONE = {"deleted": True}


def _norm(path: str, cwd: str = "/") -> str:
    if not path:
        path = "."
    if not path.startswith("/"):
        path = posixpath.join(cwd, path)
    return posixpath.normpath(path)


class Vfs:
    """Reads see overlay over base; writes land only in the overlay. The base is
    shared across sessions and never mutated here."""

    def __init__(self, base: dict[str, dict], overlay: dict[str, Any]) -> None:
        self.base = base
        self.overlay = overlay

    # -- lookups -----------------------------------------------------------
    def _node(self, path: str) -> dict | None:
        if path in self.overlay:
            node = self.overlay[path]
            return None if node is _TOMBSTONE or node == _TOMBSTONE else node
        return self.base.get(path)

    def exists(self, path: str, cwd: str = "/") -> bool:
        p = _norm(path, cwd)
        if p == "/":
            return True
        return self._node(p) is not None or self.is_dir(p)

    def is_dir(self, path: str, cwd: str = "/") -> bool:
        p = _norm(path, cwd)
        if p == "/":
            return True
        node = self._node(p)
        if node is not None:
            return node.get("type") == "dir"
        # Implicit directory: something lives beneath it.
        prefix = p.rstrip("/") + "/"
        return any(k.startswith(prefix) for k in self._all_paths())

    def is_file(self, path: str, cwd: str = "/") -> bool:
        node = self._node(_norm(path, cwd))
        return node is not None and node.get("type") == "file"

    def read(self, path: str, cwd: str = "/") -> str | None:
        node = self._node(_norm(path, cwd))
        if node is None or node.get("type") != "file":
            return None
        return node.get("content", "")

    def stat(self, path: str, cwd: str = "/") -> dict | None:
        p = _norm(path, cwd)
        node = self._node(p)
        if node is None and self.is_dir(p):
            return {"type": "dir", "mode": "drwxr-xr-x", "owner": "root", "size": 0, "mtime": "2026-10-20T00:00:00Z"}
        if node is None:
            return None
        return {
            "type": node.get("type", "file"),
            "mode": node.get("mode", "-rw-r--r--"),
            "owner": node.get("owner", "deploy"),
            "size": len(node.get("content", "")),
            "mtime": node.get("mtime", "2026-10-20T00:00:00Z"),
        }

    # -- mutations (overlay only) -----------------------------------------
    def write(self, path: str, content: str, cwd: str = "/", owner: str = "deploy") -> None:
        p = _norm(path, cwd)
        self.overlay[p] = {
            "type": "file",
            "content": content,
            "mode": "-rw-r--r--",
            "owner": owner,
            "mtime": "2026-10-26T20:00:00Z",
        }

    def mkdir(self, path: str, cwd: str = "/") -> None:
        p = _norm(path, cwd)
        self.overlay[p] = {"type": "dir", "mode": "drwxr-xr-x", "owner": "deploy", "content": ""}

    def remove(self, path: str, cwd: str = "/") -> bool:
        p = _norm(path, cwd)
        if not self.exists(p):
            return False
        self.overlay[p] = dict(_TOMBSTONE)
        return True

    # -- listings ----------------------------------------------------------
    def _all_paths(self) -> set[str]:
        paths = set(self.base.keys())
        for k, v in self.overlay.items():
            if v is _TOMBSTONE or v == _TOMBSTONE:
                paths.discard(k)
            else:
                paths.add(k)
        return paths

    def listdir(self, path: str, cwd: str = "/") -> list[str]:
        p = _norm(path, cwd)
        prefix = "/" if p == "/" else p.rstrip("/") + "/"
        names: set[str] = set()
        for full in self._all_paths():
            if full.startswith(prefix) and full != p:
                rest = full[len(prefix):]
                names.add(rest.split("/", 1)[0])
        return sorted(names)

    def overlay_size(self) -> int:
        return sum(len(v.get("content", "")) for v in self.overlay.values() if isinstance(v, dict) and "content" in v)

    def written_files(self) -> dict[str, str]:
        """Files created/changed in this overlay (for lived-in carryover)."""
        return {
            k: v.get("content", "")
            for k, v in self.overlay.items()
            if isinstance(v, dict) and v.get("type") == "file"
        }
