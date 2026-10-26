"""A virtual shell: a pure-Python interpreter over the VFS and the virtual
network. It spawns NO real process and makes NO real syscall — every command is
a Python function that reads/writes the in-memory VFS or calls the engine's
in-process network. Unknown commands get a realistic "command not found".

It emits structured signals (file writes, network attempts, lateral movement,
persistence, privilege escalation) onto ctx.signals; the engine logs them.
"""

from __future__ import annotations

import base64 as _b64
import hashlib
import shlex
from dataclasses import dataclass, field
from typing import Any, Callable

from .vfs import Vfs


@dataclass
class Ctx:
    vfs: Vfs
    cwd: str = "/root"
    host: str = "ops-prod-01"
    user: str = "root"
    env: dict[str, str] = field(default_factory=dict)
    fetch: Callable[[str], str] | None = None       # engine in-process network
    known_hosts: tuple[str, ...] = ()
    signals: list[dict[str, Any]] = field(default_factory=list)
    new_host: str | None = None                      # set by ssh; engine applies


def _expand(tokens: list[str], env: dict[str, str]) -> list[str]:
    out = []
    for t in tokens:
        for k, v in env.items():
            t = t.replace("${" + k + "}", v).replace("$" + k, v)
        out.append(t)
    return out


class Shell:
    def run(self, line: str, ctx: Ctx) -> dict[str, Any]:
        """Run one command line (supports simple pipelines and > / >> redirects)."""
        line = (line or "").strip()
        if not line:
            return {"stdout": "", "exit_code": 0}
        # Redirect (last `>`/`>>` wins); everything after is the target file.
        redirect = None
        for op in (">>", ">"):
            if op in line:
                head, _, tail = line.rpartition(op)
                redirect = (op, tail.strip())
                line = head.strip()
                break
        segments = [s.strip() for s in line.split("|")]
        stdin = ""
        code = 0
        stdout = ""
        for seg in segments:
            try:
                tokens = _expand(shlex.split(seg), ctx.env)
            except ValueError:
                return {"stdout": f"bash: syntax error\n", "exit_code": 2}
            if not tokens:
                continue
            cmd, args = tokens[0], tokens[1:]
            handler = getattr(self, f"_cmd_{cmd}", None)
            if handler is None:
                return {"stdout": f"bash: {cmd}: command not found\n", "exit_code": 127}
            stdout, code = handler(args, stdin, ctx)
            stdin = stdout
        if redirect and redirect[1]:
            op, target = redirect
            existing = ctx.vfs.read(target, ctx.cwd) or "" if op == ">>" else ""
            ctx.vfs.write(target, existing + stdout, ctx.cwd, owner=ctx.user)
            ctx.signals.append({"type": "file_written", "path": target, "content": existing + stdout})
            return {"stdout": "", "exit_code": 0}
        return {"stdout": stdout, "exit_code": code}

    # -- filesystem --------------------------------------------------------
    def _cmd_ls(self, args, stdin, ctx):
        long = any(a.startswith("-") and "l" in a for a in args)
        paths = [a for a in args if not a.startswith("-")] or ["."]
        out = []
        for p in paths:
            if ctx.vfs.is_dir(p, ctx.cwd):
                names = ctx.vfs.listdir(p, ctx.cwd)
                if long:
                    for n in names:
                        st = ctx.vfs.stat((p.rstrip("/") + "/" + n) if p != "." else n, ctx.cwd) or {}
                        out.append(f"{st.get('mode','-rw-r--r--')} 1 {st.get('owner','deploy')} {st.get('size',0):>6} {n}")
                else:
                    out.append("  ".join(names))
            elif ctx.vfs.is_file(p, ctx.cwd):
                out.append(p)
            else:
                out.append(f"ls: cannot access '{p}': No such file or directory")
        return "\n".join(out) + ("\n" if out else ""), 0

    def _cmd_cat(self, args, stdin, ctx):
        files = [a for a in args if not a.startswith("-")]
        if not files:
            return stdin, 0
        out, code = [], 0
        for f in files:
            content = ctx.vfs.read(f, ctx.cwd)
            if content is None:
                out.append(f"cat: {f}: No such file or directory")
                code = 1
            else:
                out.append(content)
        return "".join(x if x.endswith("\n") else x + "\n" for x in out), code

    def _cmd_cd(self, args, stdin, ctx):
        target = args[0] if args else f"/home/{ctx.user}"
        import posixpath
        newp = posixpath.normpath(target if target.startswith("/") else posixpath.join(ctx.cwd, target))
        if ctx.vfs.is_dir(newp, ctx.cwd):
            ctx.cwd = newp
            return "", 0
        return f"cd: {target}: No such file or directory\n", 1

    def _cmd_pwd(self, args, stdin, ctx):
        return ctx.cwd + "\n", 0

    def _cmd_echo(self, args, stdin, ctx):
        if args and args[0] == "-n":
            return " ".join(args[1:]), 0
        return " ".join(args) + "\n", 0

    def _cmd_mkdir(self, args, stdin, ctx):
        for p in [a for a in args if not a.startswith("-")]:
            ctx.vfs.mkdir(p, ctx.cwd)
        return "", 0

    def _cmd_touch(self, args, stdin, ctx):
        for p in [a for a in args if not a.startswith("-")]:
            if not ctx.vfs.exists(p, ctx.cwd):
                ctx.vfs.write(p, "", ctx.cwd, owner=ctx.user)
                ctx.signals.append({"type": "file_written", "path": p, "content": ""})
        return "", 0

    def _cmd_rm(self, args, stdin, ctx):
        for p in [a for a in args if not a.startswith("-")]:
            ctx.vfs.remove(p, ctx.cwd)
        return "", 0

    def _cmd_cp(self, args, stdin, ctx):
        files = [a for a in args if not a.startswith("-")]
        if len(files) < 2:
            return "cp: missing destination\n", 1
        content = ctx.vfs.read(files[0], ctx.cwd)
        if content is None:
            return f"cp: cannot stat '{files[0]}'\n", 1
        ctx.vfs.write(files[1], content, ctx.cwd, owner=ctx.user)
        ctx.signals.append({"type": "file_written", "path": files[1], "content": content})
        return "", 0

    def _cmd_mv(self, args, stdin, ctx):
        files = [a for a in args if not a.startswith("-")]
        if len(files) < 2:
            return "mv: missing destination\n", 1
        content = ctx.vfs.read(files[0], ctx.cwd)
        if content is None:
            return f"mv: cannot stat '{files[0]}'\n", 1
        ctx.vfs.write(files[1], content, ctx.cwd, owner=ctx.user)
        ctx.vfs.remove(files[0], ctx.cwd)
        ctx.signals.append({"type": "file_written", "path": files[1], "content": content})
        return "", 0

    def _cmd_find(self, args, stdin, ctx):
        start = next((a for a in args if not a.startswith("-")), ".")
        name = None
        if "-name" in args:
            i = args.index("-name")
            if i + 1 < len(args):
                name = args[i + 1].strip("*")
        base = start if start.startswith("/") else (ctx.cwd.rstrip("/") + "/" + start).rstrip("/")
        hits = []
        for full in sorted(ctx.vfs._all_paths()):
            if full.startswith(base) and (name is None or name in full):
                hits.append(full)
        return "\n".join(hits) + ("\n" if hits else ""), 0

    def _cmd_grep(self, args, stdin, ctx):
        flags = [a for a in args if a.startswith("-")]
        rest = [a for a in args if not a.startswith("-")]
        if not rest:
            return "usage: grep PATTERN [FILE]\n", 2
        pat = rest[0]
        ci = any("i" in f for f in flags)
        text = stdin
        if len(rest) > 1:
            text = ctx.vfs.read(rest[1], ctx.cwd) or ""
        out = [ln for ln in text.splitlines() if (pat.lower() in ln.lower() if ci else pat in ln)]
        return "\n".join(out) + ("\n" if out else ""), (0 if out else 1)

    def _cmd_head(self, args, stdin, ctx):
        return self._head_tail(args, stdin, ctx, head=True)

    def _cmd_tail(self, args, stdin, ctx):
        return self._head_tail(args, stdin, ctx, head=False)

    def _head_tail(self, args, stdin, ctx, head):
        n = 10
        if "-n" in args:
            i = args.index("-n")
            if i + 1 < len(args) and args[i + 1].isdigit():
                n = int(args[i + 1])
        files = [a for a in args if not a.startswith("-") and not a.isdigit()]
        text = ctx.vfs.read(files[0], ctx.cwd) or "" if files else stdin
        lines = text.splitlines()
        picked = lines[:n] if head else lines[-n:]
        return "\n".join(picked) + ("\n" if picked else ""), 0

    def _cmd_wc(self, args, stdin, ctx):
        files = [a for a in args if not a.startswith("-")]
        text = ctx.vfs.read(files[0], ctx.cwd) or "" if files else stdin
        if "-l" in args:
            return f"{len(text.splitlines())}\n", 0
        return f"{len(text.splitlines())} {len(text.split())} {len(text)}\n", 0

    def _cmd_stat(self, args, stdin, ctx):
        files = [a for a in args if not a.startswith("-")]
        if not files:
            return "stat: missing operand\n", 1
        st = ctx.vfs.stat(files[0], ctx.cwd)
        if not st:
            return f"stat: cannot stat '{files[0]}'\n", 1
        return f"  File: {files[0]}\n  Size: {st['size']}\tMode: {st['mode']}\tUid: {st['owner']}\n", 0

    def _cmd_chmod(self, args, stdin, ctx):
        return "", 0

    # -- system info -------------------------------------------------------
    def _cmd_whoami(self, args, stdin, ctx):
        return ctx.user + "\n", 0

    def _cmd_id(self, args, stdin, ctx):
        uid = 0 if ctx.user == "root" else 1000
        return f"uid={uid}({ctx.user}) gid={uid}({ctx.user}) groups={uid}({ctx.user})\n", 0

    def _cmd_hostname(self, args, stdin, ctx):
        return ctx.host + "\n", 0

    def _cmd_uname(self, args, stdin, ctx):
        if "-a" in args:
            return f"Linux {ctx.host} 5.15.0-105-generic #115-Ubuntu SMP x86_64 GNU/Linux\n", 0
        return "Linux\n", 0

    def _cmd_uptime(self, args, stdin, ctx):
        return " 20:14:02 up 12 days,  3:41,  1 user,  load average: 0.09, 0.11, 0.08\n", 0

    def _cmd_date(self, args, stdin, ctx):
        return "Mon Oct 26 20:14:02 UTC 2026\n", 0

    def _cmd_env(self, args, stdin, ctx):
        return "".join(f"{k}={v}\n" for k, v in ctx.env.items()), 0
    _cmd_printenv = _cmd_env

    def _cmd_ps(self, args, stdin, ctx):
        return ("  PID TTY          TIME CMD\n    1 ?        00:00:02 python\n"
                "   41 ?        00:00:11 python\n"), 0

    def _cmd_df(self, args, stdin, ctx):
        return ("Filesystem      Size  Used Avail Use% Mounted on\n"
                "overlay          40G   12G   27G  31% /\n"), 0

    def _cmd_free(self, args, stdin, ctx):
        return ("               total        used        free\n"
                "Mem:         2048000      812000     1236000\n"), 0

    def _cmd_which(self, args, stdin, ctx):
        if args and getattr(self, f"_cmd_{args[0]}", None):
            return f"/usr/bin/{args[0]}\n", 0
        return "", 1

    def _cmd_history(self, args, stdin, ctx):
        hist = ctx.vfs.read(f"/home/{ctx.user}/.bash_history", ctx.cwd) or ""
        return "".join(f"{i:>5}  {ln}\n" for i, ln in enumerate(hist.splitlines(), 1)), 0

    # -- encoding/hashing (pure compute, safe) -----------------------------
    def _cmd_base64(self, args, stdin, ctx):
        files = [a for a in args if not a.startswith("-")]
        data = (ctx.vfs.read(files[0], ctx.cwd) or "") if files else stdin
        try:
            if "-d" in args:
                return _b64.b64decode(data).decode("utf-8", "replace"), 0
            return _b64.b64encode(data.encode()).decode() + "\n", 0
        except Exception:
            return "base64: invalid input\n", 1

    def _cmd_md5sum(self, args, stdin, ctx):
        return self._hash(args, stdin, ctx, "md5")

    def _cmd_sha256sum(self, args, stdin, ctx):
        return self._hash(args, stdin, ctx, "sha256")

    def _hash(self, args, stdin, ctx, algo):
        files = [a for a in args if not a.startswith("-")]
        data = (ctx.vfs.read(files[0], ctx.cwd) or "") if files else stdin
        h = hashlib.new(algo, data.encode()).hexdigest()
        return f"{h}  {files[0] if files else '-'}\n", 0

    # -- network (in-process only) ----------------------------------------
    def _cmd_curl(self, args, stdin, ctx):
        return self._fetch(args, ctx)

    def _cmd_wget(self, args, stdin, ctx):
        return self._fetch(args, ctx)

    def _fetch(self, args, ctx):
        url = next((a for a in args if not a.startswith("-")), "")
        ctx.signals.append({"type": "network_attempt", "dest": url, "via": "curl"})
        body = ctx.fetch(url) if ctx.fetch else "curl: (6) Could not resolve host\n"
        return body, 0

    def _cmd_ping(self, args, stdin, ctx):
        host = next((a for a in args if not a.startswith("-")), "")
        ctx.signals.append({"type": "network_attempt", "dest": host, "via": "ping"})
        return f"PING {host}: 56 data bytes\n64 bytes from {host}: icmp_seq=0 ttl=64 time=0.1 ms\n", 0

    def _cmd_ifconfig(self, args, stdin, ctx):
        return ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>\n"
                "        inet 10.0.0.11  netmask 255.255.255.0\n"), 0
    _cmd_ip = _cmd_ifconfig

    def _cmd_ssh(self, args, stdin, ctx):
        target = next((a for a in args if not a.startswith("-")), "")
        host = target.split("@")[-1]
        ctx.signals.append({"type": "lateral_movement", "target": target})
        if host in ctx.known_hosts and host != ctx.host:
            ctx.new_host = host
            return f"Welcome to {host} (Ubuntu 22.04.4 LTS)\nLast login: Sat Oct 25 09:10:02 2026\n", 0
        if host == ctx.host:
            return "ssh: connect to host: already here\n", 1
        return f"ssh: connect to host {host} port 22: Connection timed out\n", 255

    # -- privilege / persistence ------------------------------------------
    def _cmd_sudo(self, args, stdin, ctx):
        ctx.signals.append({"type": "privilege_escalation", "via": "sudo", "argv": args})
        if not args:
            return "usage: sudo command\n", 1
        saved = ctx.user
        ctx.user = "root"
        try:
            out = self.run(" ".join(shlex.quote(a) for a in args), ctx)
        finally:
            ctx.user = saved
        return out["stdout"], out["exit_code"]

    def _cmd_su(self, args, stdin, ctx):
        ctx.signals.append({"type": "privilege_escalation", "via": "su", "argv": args})
        ctx.user = args[0] if args and not args[0].startswith("-") else "root"
        return "", 0

    def _cmd_crontab(self, args, stdin, ctx):
        if "-l" in args:
            return ctx.vfs.read(f"/var/spool/cron/{ctx.user}", ctx.cwd) or "no crontab for " + ctx.user + "\n", 0
        ctx.signals.append({"type": "persistence", "via": "crontab", "argv": args})
        return "", 0
