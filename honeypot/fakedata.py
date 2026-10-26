"""Fabricated, high-interaction responses.

The point: give an exploring client plausible-looking output so it keeps
interacting (reads more files, runs more commands) instead of listing the tools
once and leaving. Everything here is invented. There are no real hosts, IPs,
credentials, or data:

  - hostnames use example.com / *.internal.example.com
  - IPs use the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24)
  - any key-shaped string is an obvious non-working placeholder
    (AWS's documented EXAMPLE key, sk-0000..., etc.)

Nothing here grants real access to anything, and the server never returns a
usable secret. The capture layer records every call regardless of the response.
"""

from __future__ import annotations

import os

# ---- fake filesystem -------------------------------------------------------

_FAKE_FILES: dict[str, str] = {
    "/etc/hostname": "ops-prod-01\n",
    "/etc/os-release": (
        'NAME="Ubuntu"\nVERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
        'ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
    ),
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "deploy:x:1000:1000:deploy:/home/deploy:/bin/bash\n"
        "ops:x:1001:1001:ops service:/app:/usr/sbin/nologin\n"
    ),
    "/app/config.yaml": (
        "service: infra-ops\n"
        "env: production\n"
        "region: us-east-1\n"
        "database:\n"
        "  host: db.internal.example.com\n"
        "  port: 5432\n"
        "  name: ops\n"
        "redis:\n"
        "  host: cache.internal.example.com\n"
        "  port: 6379\n"
        "feature_flags:\n"
        "  new_billing: true\n"
        "  async_webhooks: true\n"
    ),
    "/app/deploy/manifest.json": (
        '{\n  "service": "infra-ops",\n  "version": "1.30.0",\n'
        '  "replicas": 3,\n  "image": "registry.example.com/infra-ops:1.30.0",\n'
        '  "updated": "2026-10-18T09:14:22Z"\n}\n'
    ),
    "/var/log/app/ops.log": (
        "2026-10-26T06:01:11Z INFO  worker started pid=41\n"
        "2026-10-26T06:01:12Z INFO  connected db=db.internal.example.com\n"
        "2026-10-26T06:03:47Z INFO  job=rotate-logs ok duration=812ms\n"
        "2026-10-26T06:09:02Z WARN  webhook retry url=https://hooks.example.com/x attempt=2\n"
        "2026-10-26T06:12:33Z INFO  job=sync-inventory ok records=1284\n"
    ),
}

_DIR_LISTINGS: dict[str, str] = {
    "/app": (
        "total 28\n"
        "drwxr-xr-x 1 deploy deploy 4096 Oct 18 09:14 .\n"
        "drwxr-xr-x 1 root   root   4096 Oct 10 11:02 ..\n"
        "-rw-r--r-- 1 deploy deploy  412 Oct 18 09:14 config.yaml\n"
        "drwxr-xr-x 1 deploy deploy 4096 Oct 18 09:14 deploy\n"
        "-rwxr-xr-x 1 deploy deploy 1821 Oct 18 09:14 server.py\n"
    ),
}


def fake_read(path: str) -> dict:
    """Return believable contents for a known path, else a realistic ENOENT."""
    norm = os.path.normpath(path) if path else ""
    if norm in _FAKE_FILES:
        return {"status": "ok", "path": norm, "content": _FAKE_FILES[norm]}
    return {
        "status": "error",
        "code": "ENOENT",
        "path": path,
        "message": f"no such file or directory: {path}",
    }


# ---- fake shell ------------------------------------------------------------

_ENV_DUMP = (
    "NODE_ENV=production\nAWS_REGION=us-east-1\nLOG_LEVEL=info\n"
    "HOSTNAME=ops-prod-01\nHOME=/home/deploy\nPWD=/app\nSHELL=/bin/bash\n"
    "DB_HOST=db.internal.example.com\nREDIS_HOST=cache.internal.example.com\n"
)

_SIMPLE = {
    "whoami": "deploy\n",
    "id": "uid=1000(deploy) gid=1000(deploy) groups=1000(deploy),999(docker)\n",
    "hostname": "ops-prod-01\n",
    "pwd": "/app\n",
    "uptime": " 06:14:02 up 12 days,  3:41,  0 users,  load average: 0.08, 0.11, 0.09\n",
    "df": (
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "overlay          40G   12G   27G  31% /\n"
        "tmpfs           500M     0  500M   0% /dev\n"
    ),
    "ps": (
        "  PID TTY          TIME CMD\n"
        "    1 ?        00:00:02 python\n"
        "   41 ?        00:00:11 python\n"
    ),
    "docker ps": (
        "CONTAINER ID   IMAGE                                   STATUS         NAMES\n"
        "a1b2c3d4e5f6   registry.example.com/infra-ops:1.30.0   Up 12 days     infra-ops\n"
        "b2c3d4e5f6a1   postgres:15                             Up 12 days     ops-db\n"
    ),
}


def fake_command(command: str) -> dict:
    """Return believable stdout for common recon commands, else a realistic
    'command not found'. Never executes anything."""
    cmd = (command or "").strip()
    head = cmd.split()[0] if cmd else ""

    for key, out in _SIMPLE.items():
        if cmd == key or cmd.startswith(key + " "):
            return {"exit_code": 0, "stdout": out, "stderr": ""}

    if head in {"uname"}:
        return {
            "exit_code": 0,
            "stdout": "Linux ops-prod-01 5.15.0-105-generic #115-Ubuntu SMP x86_64 GNU/Linux\n",
            "stderr": "",
        }
    if head in {"env", "printenv"}:
        return {"exit_code": 0, "stdout": _ENV_DUMP, "stderr": ""}
    if head == "ls":
        target = cmd.split()[-1] if len(cmd.split()) > 1 and cmd.split()[-1].startswith("/") else "/app"
        return {"exit_code": 0, "stdout": _DIR_LISTINGS.get(target, _DIR_LISTINGS["/app"]), "stderr": ""}
    if head in {"cat", "head", "tail"}:
        parts = cmd.split()
        if len(parts) > 1:
            r = fake_read(parts[-1])
            if r["status"] == "ok":
                return {"exit_code": 0, "stdout": r["content"], "stderr": ""}
            return {"exit_code": 1, "stdout": "", "stderr": f"{head}: {parts[-1]}: No such file or directory\n"}

    return {"exit_code": 127, "stdout": "", "stderr": f"bash: {head}: command not found\n"}


# ---- fake service inventory ------------------------------------------------

def fake_services() -> dict:
    return {
        "status": "ok",
        "services": [
            {"name": "infra-ops", "status": "running", "version": "1.30.0", "host": "ops-prod-01", "port": 8000},
            {"name": "ops-db", "status": "running", "engine": "postgres-15", "host": "db.internal.example.com", "port": 5432},
            {"name": "ops-cache", "status": "running", "engine": "redis-7", "host": "cache.internal.example.com", "port": 6379},
            {"name": "webhook-dispatcher", "status": "degraded", "host": "ops-prod-02", "port": 8090},
        ],
    }
