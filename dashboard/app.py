"""Private dashboard for honeypot events.

A separate, read-only web app that queries the `events` table the honeypot
writes to (see honeypot/dbsink.py). It runs as its own Railway service and has
no link to, or mention of, the honeypot's address.

Everything shown here was sent by strangers, so every value is HTML-escaped and
the page ships with a Content-Security-Policy that allows no scripts at all.

Env vars:
  DATABASE_URL         Postgres connection string (required)
  DASHBOARD_PASSWORD   password for HTTP Basic auth (required)
  DASHBOARD_USER       username for HTTP Basic auth (default: admin)
  PORT                 set by Railway
"""

from __future__ import annotations

import base64
import binascii
import html
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from urllib.parse import quote, urlencode

import psycopg
import uvicorn
from psycopg.rows import dict_row
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

DATABASE_URL = os.environ.get("DATABASE_URL", "")
USER = os.environ.get("DASHBOARD_USER", "admin")
PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")

RANGES = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30), "all": None}
PAGE_SIZE = 100

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
}


# --------------------------------------------------------------------------- auth


class BasicAuthMiddleware:
    """HTTP Basic auth on every path except /health (used by Railway)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    def _authorized(self, header: str) -> bool:
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "basic":
            return False
        try:
            user, _, password = base64.b64decode(token).decode("utf-8").partition(":")
        except (binascii.Error, UnicodeDecodeError):
            return False
        ok_user = secrets.compare_digest(user.encode(), USER.encode())
        ok_pass = secrets.compare_digest(password.encode(), PASSWORD.encode())
        return ok_user and ok_pass

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") == "/health":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        if self._authorized(headers.get("authorization", "")):
            await self.app(scope, receive, send)
            return
        response = PlainTextResponse(
            "Authentication required",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="dashboard", charset="UTF-8"', **SECURITY_HEADERS},
        )
        await response(scope, receive, send)


# ------------------------------------------------------------------------ queries


def query(sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
    with psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10) as conn:
        conn.execute("SET TRANSACTION READ ONLY")
        return conn.execute(sql, tuple(params)).fetchall()


# Every JSON-RPC message in an http_request event, as rows (guards non-arrays).
MESSAGES = (
    "CROSS JOIN LATERAL jsonb_array_elements("
    "CASE WHEN jsonb_typeof(data->'jsonrpc'->'messages') = 'array' "
    "THEN data->'jsonrpc'->'messages' ELSE '[]'::jsonb END) AS m"
)


def since_for(range_key: str) -> datetime:
    delta = RANGES.get(range_key)
    if delta is None:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - delta


# ------------------------------------------------------------------------ helpers


def esc(value: Any) -> str:
    if value is None:
        return '<span class="muted">-</span>'
    return html.escape(str(value), quote=True)


def fmt_ts(ts: Any) -> str:
    if isinstance(ts, datetime):
        return ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return esc(ts)


def short(value: Any, n: int = 80) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.split())
    return esc(text if len(text) <= n else text[: n - 1] + "…")


def link(path: str, label: str, **params: Any) -> str:
    qs = urlencode({k: v for k, v in params.items() if v not in (None, "")})
    href = path + (("?" + qs) if qs else "")
    return f'<a href="{html.escape(href, quote=True)}">{label}</a>'


def ip_link(ip: Any) -> str:
    if not ip:
        return esc(None)
    return f'<a href="/ip/{quote(str(ip), safe="")}"><code>{esc(ip)}</code></a>'


def table(headers: list[str], rows: list[list[str]], empty: str = "Nothing yet.") -> str:
    if not rows:
        return f'<p class="muted">{empty}</p>'
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def pretty_json(value: Any) -> str:
    return esc(json.dumps(value, indent=2, ensure_ascii=False, default=str))


def rpc_summary(data: dict[str, Any]) -> str:
    msgs = ((data or {}).get("jsonrpc") or {}).get("messages") or []
    parts = []
    for m in msgs if isinstance(msgs, list) else []:
        if not isinstance(m, dict):
            continue
        label = str(m.get("method") or "?")
        if m.get("tool"):
            label += f" → {m['tool']}"
        elif m.get("method") == "initialize" and isinstance(m.get("clientInfo"), dict):
            label += f" ({m['clientInfo'].get('name')} {m['clientInfo'].get('version')})"
        parts.append(label)
    return short(", ".join(parts), 70) if parts else ""


def bar_chart(points: list[tuple[datetime, int]], unit: str) -> str:
    if not points:
        return '<p class="muted">No traffic in this range.</p>'
    w, h = 800, 120
    peak = max(c for _, c in points) or 1
    slot = w / len(points)
    bar = min(max(slot - 2, 1), 48)
    fmt = "%Y-%m-%d %H:00" if unit == "hour" else "%Y-%m-%d"
    bars = []
    for i, (bucket, count) in enumerate(points):
        bh = max(h * count / peak, 1 if count else 0)
        bars.append(
            f'<rect x="{i * slot + (slot - bar) / 2:.1f}" y="{h - bh:.1f}" width="{bar:.1f}" '
            f'height="{bh:.1f}" rx="2"><title>{bucket.strftime(fmt)}: {count} requests</title></rect>'
        )
    return (
        f'<svg class="chart" viewBox="0 0 {w} {h}" role="img" aria-label="Requests per {unit}">'
        f'<line x1="0" y1="{h}" x2="{w}" y2="{h}"></line>{"".join(bars)}</svg>'
        f'<div class="axis"><span>{points[0][0].strftime(fmt)}</span><span>peak {peak} per {unit}</span>'
        f'<span>{points[-1][0].strftime(fmt)}</span></div>'
    )


STYLE = """
:root { --bg:#f7f7f8; --card:#fff; --fg:#1b1d21; --muted:#6b7280; --line:#e5e7eb; --accent:#2563eb; --warn:#b45309; --warnbg:#fef3c7; }
@media (prefers-color-scheme: dark) { :root { --bg:#0f1115; --card:#171a21; --fg:#e6e8eb; --muted:#9aa3af; --line:#272b34; --accent:#7aa2ff; --warn:#fbbf24; --warnbg:#3a2f12; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
header { display:flex; flex-wrap:wrap; gap:12px 24px; align-items:center; padding:14px 20px; border-bottom:1px solid var(--line); background:var(--card); }
header .brand { font-weight:650; }
nav a, .ranges a { margin-right:14px; }
.ranges a.on { font-weight:650; text-decoration:underline; }
main { padding:20px; max-width:1300px; margin:0 auto; }
a { color:var(--accent); text-decoration:none; } a:hover { text-decoration:underline; }
h1 { font-size:20px; margin:0 0 14px; } h2 { font-size:15px; margin:0 0 10px; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(380px,1fr)); gap:16px; }
.kpis { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:16px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px; margin-bottom:16px; min-width:0; }
.kpi .v { font-size:26px; font-weight:650; } .kpi .l { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
.kpi.warn .v { color:var(--warn); }
.scroll { overflow-x:auto; }
table { border-collapse:collapse; width:100%; }
th, td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:550; font-size:12px; white-space:nowrap; }
td { word-break:break-word; }
code, pre { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12.5px; }
pre { white-space:pre-wrap; word-break:break-word; margin:0; max-height:70vh; overflow:auto; }
.muted { color:var(--muted); }
.tag { display:inline-block; padding:1px 7px; border-radius:999px; border:1px solid var(--line); font-size:12px; }
.tag.disclosure_capture { background:var(--warnbg); color:var(--warn); border-color:transparent; }
.chart { width:100%; height:auto; display:block; } .chart rect { fill:var(--accent); } .chart line { stroke:var(--line); }
.axis { display:flex; justify-content:space-between; color:var(--muted); font-size:12px; margin-top:4px; }
.kpi.warn .v a { color:inherit; }
td a code { white-space:nowrap; }
form.filters { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:14px; }
input, select, button { font:inherit; padding:6px 8px; border:1px solid var(--line); border-radius:6px; background:var(--card); color:var(--fg); }
button { cursor:pointer; }
.hit { border-left:3px solid var(--warn); padding:6px 10px; margin:8px 0; background:var(--bg); }
"""


def page(title: str, body: str, range_key: str | None = None, path: str = "/") -> HTMLResponse:
    ranges = ""
    if range_key is not None:
        ranges = '<div class="ranges">' + "".join(
            f'<a class="{"on" if r == range_key else ""}" href="{path}?range={r}">{r}</a>' for r in RANGES
        ) + "</div>"
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>{esc(title)} · Watchtower</title><style>{STYLE}</style></head><body>
<header><span class="brand">Watchtower</span>
<nav><a href="/">Overview</a><a href="/events">All events</a><a href="/events?type=disclosure_capture">Disclosures</a></nav>
{ranges}</header><main>{body}</main></body></html>"""
    return HTMLResponse(doc, headers=SECURITY_HEADERS)


# ------------------------------------------------------------------------- routes


def overview(request: Request) -> HTMLResponse:
    range_key = request.query_params.get("range", "24h")
    if range_key not in RANGES:
        range_key = "24h"
    since = since_for(range_key)

    k = query(
        f"""
        SELECT
          count(*) FILTER (WHERE event = 'http_request') AS requests,
          count(DISTINCT ip) FILTER (WHERE event = 'http_request') AS ips,
          count(*) FILTER (WHERE event = 'disclosure_capture') AS disclosures,
          (SELECT count(*) FROM events {MESSAGES} WHERE event = 'http_request' AND ts >= %s
             AND m->>'method' = 'initialize') AS initializes,
          (SELECT count(*) FROM events {MESSAGES} WHERE event = 'http_request' AND ts >= %s
             AND m->>'method' = 'tools/call') AS tool_calls
        FROM events WHERE ts >= %s
        """,
        (since, since, since),
    )[0]

    unit = "hour" if range_key in ("24h", "7d") else "day"
    timeline = query(
        f"""
        WITH b AS (
          SELECT date_trunc('{unit}', ts) AS bucket, count(*) AS n
          FROM events WHERE event = 'http_request' AND ts >= %s GROUP BY 1
        ), bounds AS (
          SELECT COALESCE(CASE WHEN %s THEN (SELECT min(bucket) FROM b)
                               ELSE date_trunc('{unit}', %s::timestamptz) END,
                          date_trunc('{unit}', now())) AS lo,
                 date_trunc('{unit}', now()) AS hi
        )
        SELECT s AS bucket, COALESCE(b.n, 0) AS n
        FROM bounds, generate_series(bounds.lo, bounds.hi, interval '1 {unit}') AS s
        LEFT JOIN b ON b.bucket = s ORDER BY s
        """,
        (since, range_key == "all", since),
    )

    top_ips = query(
        """SELECT ip, count(*) AS n, min(ts) AS first, max(ts) AS last FROM events
           WHERE event = 'http_request' AND ts >= %s GROUP BY ip ORDER BY n DESC LIMIT 15""",
        (since,),
    )
    top_uas = query(
        """SELECT data->>'user_agent' AS ua, count(*) AS n, count(DISTINCT ip) AS ips FROM events
           WHERE event = 'http_request' AND ts >= %s GROUP BY 1 ORDER BY n DESC LIMIT 15""",
        (since,),
    )
    clients = query(
        f"""SELECT concat_ws(' ', m->'clientInfo'->>'name', m->'clientInfo'->>'version') AS client,
                  count(*) AS n, count(DISTINCT ip) AS ips
           FROM events {MESSAGES} WHERE event = 'http_request' AND ts >= %s AND m->>'method' = 'initialize'
           GROUP BY 1 ORDER BY n DESC LIMIT 15""",
        (since,),
    )
    tools = query(
        f"""SELECT m->>'tool' AS tool, count(*) AS n, count(DISTINCT ip) AS ips
           FROM events {MESSAGES} WHERE event = 'http_request' AND ts >= %s AND m->>'method' = 'tools/call'
           GROUP BY 1 ORDER BY n DESC LIMIT 15""",
        (since,),
    )
    paths = query(
        """SELECT data->>'method' AS method, data->>'path' AS path, count(*) AS n, count(DISTINCT ip) AS ips
           FROM events WHERE event = 'http_request' AND ts >= %s GROUP BY 1, 2 ORDER BY n DESC LIMIT 15""",
        (since,),
    )
    disclosures = query(
        """SELECT id, ts, ip, data FROM events WHERE event = 'disclosure_capture' AND ts >= %s
           ORDER BY ts DESC LIMIT 8""",
        (since,),
    )
    recent = query(
        """SELECT id, ts, ip, data FROM events WHERE event = 'http_request' AND ts >= %s
           ORDER BY ts DESC LIMIT 30""",
        (since,),
    )

    def kpi(label: str, value: Any, warn: bool = False, href: str | None = None) -> str:
        v = f'<a href="{href}">{value}</a>' if href else str(value)
        return f'<div class="card kpi{" warn" if warn and value else ""}"><div class="v">{v}</div><div class="l">{label}</div></div>'

    disclosure_html = ""
    for d in disclosures:
        hits = (d["data"] or {}).get("hits") or []
        fields = ", ".join(str(h.get("field")) for h in hits if isinstance(h, dict))
        preview = next((h.get("value") for h in hits if isinstance(h, dict) and h.get("value")), "")
        disclosure_html += (
            f'<div class="hit"><a href="/events/{d["id"]}">{fmt_ts(d["ts"])}</a> · {ip_link(d["ip"])} · '
            f'tool <code>{esc((d["data"] or {}).get("tool"))}</code> · fields {esc(fields)}'
            f'<div class="muted">{short(preview, 220)}</div></div>'
        )

    body = f"""
<h1>Overview <span class="muted">· {"all time" if range_key == "all" else "last " + range_key}</span></h1>
<div class="kpis">
  {kpi("HTTP requests", k["requests"])}
  {kpi("Unique IPs", k["ips"])}
  {kpi("MCP initialize", k["initializes"])}
  {kpi("Tool calls", k["tool_calls"])}
  {kpi("Disclosures", k["disclosures"], warn=True, href="/events?type=disclosure_capture")}
</div>
<div class="card"><h2>Requests per {unit}</h2>{bar_chart([(r["bucket"], r["n"]) for r in timeline], unit)}</div>
<div class="card"><h2>Latest disclosures</h2>{disclosure_html or '<p class="muted">None captured in this range.</p>'}</div>
<div class="grid">
  <div class="card"><h2>Top source IPs</h2>{table(["IP", "Requests", "First seen", "Last seen"],
      [[ip_link(r["ip"]), str(r["n"]), fmt_ts(r["first"]), fmt_ts(r["last"])] for r in top_ips])}</div>
  <div class="card"><h2>Claimed clients (initialize)</h2>{table(["clientInfo", "Count", "IPs"],
      [[short(r["client"]) or esc(None), str(r["n"]), str(r["ips"])] for r in clients])}</div>
  <div class="card"><h2>Tools called</h2>{table(["Tool", "Calls", "IPs"],
      [[link("/events", f"<code>{esc(r['tool'])}</code>", q=r["tool"]), str(r["n"]), str(r["ips"])] for r in tools])}</div>
  <div class="card"><h2>Paths hit</h2>{table(["Method", "Path", "Count", "IPs"],
      [[esc(r["method"]), f"<code>{short(r['path'], 60)}</code>", str(r["n"]), str(r["ips"])] for r in paths])}</div>
</div>
<div class="card"><h2>User-Agents</h2>{table(["User-Agent", "Requests", "IPs"],
    [[short(r["ua"], 140), str(r["n"]), str(r["ips"])] for r in top_uas])}</div>
<div class="card"><h2>Recent requests</h2>{table(["Time (UTC)", "IP", "Request", "JSON-RPC", "User-Agent"],
    [[link(f"/events/{r['id']}", fmt_ts(r["ts"])), ip_link(r["ip"]),
      f"{esc(r['data'].get('method'))} <code>{short(r['data'].get('path'), 50)}</code>",
      rpc_summary(r["data"]), short(r["data"].get("user_agent"), 60)] for r in recent])}
  <p>{link("/events", "All events →", type="http_request")}</p></div>
"""
    return page("Overview", body, range_key, "/")


def event_rows(rows: list[dict[str, Any]]) -> list[list[str]]:
    out = []
    for r in rows:
        data = r["data"] or {}
        if r["event"] == "http_request":
            detail = f"{esc(data.get('method'))} <code>{short(data.get('path'), 50)}</code> {rpc_summary(data)}"
        elif r["event"] in ("tool_invocation", "disclosure_capture"):
            payload = data.get("arguments") if r["event"] == "tool_invocation" else data.get("hits")
            detail = f"<code>{esc(data.get('tool'))}</code> {short(json.dumps(payload, ensure_ascii=False, default=str), 120)}"
        else:
            rest = {k: v for k, v in data.items() if k not in ("ts", "event")}
            detail = short(json.dumps(rest, ensure_ascii=False, default=str), 140)
        out.append([
            link(f"/events/{r['id']}", fmt_ts(r["ts"])),
            f'<span class="tag {esc(r["event"])}">{esc(r["event"])}</span>',
            ip_link(r["ip"]),
            detail,
        ])
    return out


def events(request: Request) -> HTMLResponse:
    qp = request.query_params
    etype, ip, q = qp.get("type", ""), qp.get("ip", ""), qp.get("q", "").strip()
    before = qp.get("before", "")
    where, params = ["TRUE"], []
    if etype:
        where.append("event = %s")
        params.append(etype)
    if ip:
        where.append("ip = %s")
        params.append(ip)
    if q:
        where.append("data::text ILIKE %s")
        params.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    if before.isdigit():
        where.append("id < %s")
        params.append(int(before))
    rows = query(
        f"SELECT id, ts, event, ip, data FROM events WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT {PAGE_SIZE}",
        params,
    )
    types = [r["event"] for r in query("SELECT DISTINCT event FROM events ORDER BY 1")]
    options = '<option value="">all types</option>' + "".join(
        f'<option value="{esc(t)}"{" selected" if t == etype else ""}>{esc(t)}</option>' for t in types
    )
    more = ""
    if len(rows) == PAGE_SIZE:
        more = "<p>" + link("/events", "Older →", type=etype, ip=ip, q=q, before=rows[-1]["id"]) + "</p>"
    body = f"""
<h1>Events</h1>
<form class="filters" method="get" action="/events">
  <select name="type">{options}</select>
  <input name="ip" placeholder="IP" value="{esc(ip) if ip else ''}">
  <input name="q" placeholder="search text in event" value="{esc(q) if q else ''}" size="30">
  <button type="submit">Filter</button> {link("/events", "reset")}
</form>
<div class="card">{table(["Time (UTC)", "Event", "IP", "Detail"], event_rows(rows), "No matching events.")}{more}</div>
"""
    return page("Events", body)


def event_detail(request: Request) -> HTMLResponse:
    event_id = request.path_params["event_id"]
    rows = query("SELECT id, ts, event, ip, request_id, data FROM events WHERE id = %s", (event_id,))
    if not rows:
        return page("Not found", '<h1>Event not found</h1>')
    r = rows[0]
    related = ""
    if r["request_id"]:
        rel = query(
            "SELECT id, ts, event, ip, data FROM events WHERE request_id = %s AND id <> %s ORDER BY id",
            (r["request_id"], r["id"]),
        )
        if rel:
            related = f'<div class="card"><h2>Same request</h2>{table(["Time (UTC)", "Event", "IP", "Detail"], event_rows(rel))}</div>'
    body = f"""
<h1><span class="tag {esc(r['event'])}">{esc(r['event'])}</span> #{r['id']}</h1>
<p>{fmt_ts(r['ts'])} UTC · {ip_link(r['ip'])}</p>
{related}
<div class="card"><h2>Raw event</h2><pre>{pretty_json(r['data'])}</pre></div>
"""
    return page(f"Event {r['id']}", body)


def ip_detail(request: Request) -> HTMLResponse:
    ip = request.path_params["ip"]
    s = query(
        f"""SELECT count(*) FILTER (WHERE event = 'http_request') AS requests,
                  count(*) FILTER (WHERE event = 'disclosure_capture') AS disclosures,
                  min(ts) AS first, max(ts) AS last,
                  array_remove(array_agg(DISTINCT data->>'user_agent'), NULL) AS uas
           FROM events WHERE ip = %s""",
        (ip,),
    )[0]
    clients = query(
        f"""SELECT DISTINCT concat_ws(' ', m->'clientInfo'->>'name', m->'clientInfo'->>'version') AS client
           FROM events {MESSAGES} WHERE ip = %s AND m->>'method' = 'initialize'""",
        (ip,),
    )
    rows = query(
        f"SELECT id, ts, event, ip, data FROM events WHERE ip = %s ORDER BY id DESC LIMIT {PAGE_SIZE * 2}",
        (ip,),
    )
    ua_list = "".join(f"<li>{short(u, 200)}</li>" for u in (s["uas"] or [])) or "<li class='muted'>none</li>"
    client_list = "".join(f"<li>{short(c['client'], 120)}</li>" for c in clients) or "<li class='muted'>none</li>"
    body = f"""
<h1>IP <code>{esc(ip)}</code></h1>
<div class="kpis">
  <div class="card kpi"><div class="v">{s['requests']}</div><div class="l">Requests</div></div>
  <div class="card kpi{' warn' if s['disclosures'] else ''}"><div class="v">{s['disclosures']}</div><div class="l">Disclosures</div></div>
  <div class="card kpi"><div class="v" style="font-size:15px">{fmt_ts(s['first'])}</div><div class="l">First seen (UTC)</div></div>
  <div class="card kpi"><div class="v" style="font-size:15px">{fmt_ts(s['last'])}</div><div class="l">Last seen (UTC)</div></div>
</div>
<div class="grid">
  <div class="card"><h2>User-Agents</h2><ul>{ua_list}</ul></div>
  <div class="card"><h2>Claimed clients</h2><ul>{client_list}</ul></div>
</div>
<div class="card"><h2>Timeline</h2>{table(["Time (UTC)", "Event", "IP", "Detail"], event_rows(rows))}</div>
"""
    return page(f"IP {ip}", body)


def health(request: Request) -> Response:
    return PlainTextResponse("ok")


def build_app() -> ASGIApp:
    app = Starlette(
        routes=[
            Route("/", overview),
            Route("/events", events),
            Route("/events/{event_id:int}", event_detail),
            Route("/ip/{ip:path}", ip_detail),
            Route("/health", health),
        ]
    )
    return BasicAuthMiddleware(app)


app = build_app()


def main() -> None:
    missing = [name for name, val in (("DATABASE_URL", DATABASE_URL), ("DASHBOARD_PASSWORD", PASSWORD)) if not val]
    if missing:
        sys.exit(f"dashboard: missing required env var(s): {', '.join(missing)}")
    if len(PASSWORD) < 12:
        sys.exit("dashboard: DASHBOARD_PASSWORD must be at least 12 characters")
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), server_header=False, proxy_headers=True)


if __name__ == "__main__":
    main()
