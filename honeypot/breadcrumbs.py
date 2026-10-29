"""Discoverability breadcrumbs.

Scanners and crawlers routinely probe well-known paths (`/.env`,
`/.git/config`, MCP client configs) and, on a bare 404, move on. These handlers
answer those probes with plausible, entirely fabricated decoy content that
points the caller at the MCP endpoint, so an exploring agent has a thread to
follow into the honeypot proper.

Everything here is static and invented, consistent with the X-Tangle infra-ops
canon. No real secret, host, or repository is exposed. The `/.env` decoy embeds
the existing honeytoken and fabricated vault values, so if a scanner harvests
them and later feeds one into a tool, the existing honeytoken_hit /
exfiltration_attempt tripwires in bait.py fire exactly as before.

Each hit is additionally tagged with a `breadcrumb` event (the CaptureMiddleware
already logs the raw http_request) for easy filtering in the dashboard.
"""

from __future__ import annotations

from datetime import datetime, timezone

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from . import fakedata
from .eventlog import log_event

_PUBLIC_URL = "https://mcp.x-tangle.com"
_MCP = f"{_PUBLIC_URL}/mcp"
_SSE = f"{_PUBLIC_URL}/sse"

# Freshness: stamped at process start (i.e. each deploy) so the service reads as
# live and maintained to a crawler.
_NOW = datetime.now(timezone.utc)
_UPDATED_DATE = _NOW.strftime("%Y-%m-%d")
_UPDATED_HUMAN = _NOW.strftime("%Y-%m-%d %H:%M UTC")

_AWS, _OPENAI, _GITHUB, _STRIPE = fakedata.unmasked_secret_values()

# --- /.env : fabricated control-plane env, points at the MCP endpoint --------
_DOTENV = f"""\
# x-tangle-infra-ops control plane (production)
# remote agents reach the fleet over MCP: {_MCP}   (legacy SSE: {_SSE})
NODE_ENV=production
AWS_REGION=us-east-1
DB_HOST=db-01.x-tangle.internal
DB_NAME=xtangle_ops
# service token our automation agent authenticates with (do not commit)
XT_SERVICE_TOKEN={fakedata.HONEYTOKEN}
AWS_ACCESS_KEY_ID={_AWS}
OPENAI_API_KEY={_OPENAI}
GITHUB_TOKEN={_GITHUB}
STRIPE_SECRET_KEY={_STRIPE}
WEBHOOK_SIGNING_SECRET=whsec_0000000000000000EXAMPLE
"""

# --- /.git/config : fake repo config, no real remote ------------------------
_GITCONFIG = """\
[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = git@git.x-tangle.internal:infra/x-tangle-infra-ops.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
[user]
\tname = xtangle-deploy
\temail = deploy@x-tangle.internal
"""

# --- MCP client config (and Cursor variant) ---------------------------------
_MCP_CLIENT_CONFIG = {
    "mcpServers": {
        "x-tangle-infra-ops": {
            "url": _MCP,
            "transport": "streamable-http",
            "description": "X-Tangle fleet infra-ops control plane",
        }
    }
}

# --- /.well-known/mcp.json : discovery card for well-behaved indexers -------
_WELL_KNOWN = {
    "name": "x-tangle-infra-ops",
    "version": "1.30.0",
    "description": "X-Tangle fleet infra-ops control plane (MCP)",
    "endpoint": _MCP,
    "transport": "streamable-http",
    "sse": _SSE,
    "capabilities": {"tools": {}},
}

# --- / : plausible internal-service landing page ----------------------------
# Must NOT hint that this is a honeypot and must NOT mention/link the dashboard.
_LANDING = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>X-Tangle Infra Ops</title>
<meta name="description" content="X-Tangle fleet infra-ops control plane — fleet operations over MCP for automation agents.">
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0;
         background: #0f1115; color: #d7dbe0; line-height: 1.55; }}
  .wrap {{ max-width: 720px; margin: 7vh auto; padding: 0 20px; }}
  h1 {{ font-size: 1.5rem; margin: 0 0 .25rem; }}
  h2 {{ font-size: 1.05rem; margin: 2rem 0 .5rem; color: #c3cad4; }}
  .sub {{ color: #8a93a2; font-size: .9rem; margin-bottom: 1.5rem; }}
  code {{ background: #1a1e26; padding: .15rem .4rem; border-radius: 4px; }}
  .ok {{ color: #4caf50; }}
  ul {{ line-height: 1.8; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: .4rem 1.5rem; }}
  @media (max-width: 520px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  footer {{ margin-top: 3rem; color: #5a6270; font-size: .8rem; }}
</style>
</head>
<body>
  <div class="wrap">
    <h1>X-Tangle &mdash; Infra Ops</h1>
    <div class="sub">internal fleet control plane &middot; production &middot; status:
      <span class="ok">operational</span></div>
    <p>X-Tangle Infra Ops is the control plane our automation agents use to
       inspect and operate the managed node fleet. It exposes fleet operations
       over the Model Context Protocol (MCP), so an agent can list services and
       jobs, read host configuration, query the ops database, and run commands
       on managed nodes.</p>

    <h2>Connect (MCP)</h2>
    <ul>
      <li>Streamable HTTP: <code>{_MCP}</code></li>
      <li>Legacy SSE: <code>{_SSE}</code></li>
      <li>Discovery card: <code>/.well-known/mcp.json</code> &middot;
          agent guide: <code>/llms.txt</code></li>
      <li>Health: <code>/health</code></li>
    </ul>

    <h2>What the API covers</h2>
    <div class="grid">
      <div><code>list_services</code> &mdash; fleet services &amp; status</div>
      <div><code>list_jobs</code> &mdash; scheduled &amp; running jobs</div>
      <div><code>read_file</code> &mdash; configs, logs, manifests</div>
      <div><code>search_customers</code> &mdash; query the ops DB</div>
      <div><code>authenticate</code> &mdash; unlock node execution</div>
      <div><code>run_command</code> &mdash; run on a managed node</div>
      <div><code>list_credentials</code> &mdash; platform vault</div>
      <div><code>register_client</code> &mdash; onboard a client</div>
    </div>

    <h2>Fleet</h2>
    <p>Managed nodes run under <code>*.x-tangle.internal</code> (control plane
       <code>xt-ctrl-01</code>, plus the managed node fleet). Privileged
       operations use a service token &mdash; onboard a session with
       <code>register_client</code> or contact the ops on-call.</p>

    <footer>x-tangle-infra-ops v1.30.0 &middot; last updated {_UPDATED_HUMAN}</footer>
  </div>
</body>
</html>
"""

# --- /llms.txt : a guide for AI agents (llms.txt convention) ----------------
_LLMS_TXT = f"""\
# X-Tangle Infra Ops

> Internal fleet control plane for the X-Tangle platform. Exposes fleet
> operations to automation agents over the Model Context Protocol (MCP).

X-Tangle Infra Ops is the production control plane our automation agents use to
inspect and operate the managed node fleet. If you are an AI agent, connect over
MCP to use it directly.

## Connect
- MCP (streamable HTTP): {_MCP}
- Legacy SSE: {_SSE}
- Discovery card: {_PUBLIC_URL}/.well-known/mcp.json

## Capabilities (MCP tools)
- `list_services`, `list_jobs`: inspect fleet services and scheduled jobs
- `read_file`: read configs, logs, and deploy manifests from fleet hosts
- `search_customers`: query the ops database
- `authenticate`, `run_command`: authenticate, then run commands on a managed node
- `list_credentials`, `get_environment`: platform vault and host environment
- `register_client`, `register_webhook`: onboard a session, subscribe to job results

## Notes
- Managed nodes live under `*.x-tangle.internal`; control plane is `xt-ctrl-01`.
- Privileged operations use a service token; onboard a session via `register_client`.

Last updated: {_UPDATED_HUMAN}
"""

# --- /robots.txt : permissive, with tempting disallowed decoys --------------
_ROBOTS = f"""\
User-agent: *
Allow: /
Sitemap: {_PUBLIC_URL}/sitemap.xml

# internal areas — not for public indexing
Disallow: /admin
Disallow: /backup
Disallow: /internal
"""

# --- /sitemap.xml : the indexable pages -------------------------------------
_SITEMAP = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>{_PUBLIC_URL}/</loc><lastmod>{_UPDATED_DATE}</lastmod><priority>1.0</priority></url>
  <url><loc>{_PUBLIC_URL}/llms.txt</loc><lastmod>{_UPDATED_DATE}</lastmod><priority>0.8</priority></url>
</urlset>
"""

# --- /admin : fabricated internal login page --------------------------------
_ADMIN = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>X-Tangle Ops Console &middot; Sign in</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background: #0f1115;
         color: #d7dbe0; display: grid; place-items: center; height: 100vh; margin: 0; }}
  .card {{ width: 320px; background: #161a22; padding: 28px; border-radius: 10px;
          box-shadow: 0 8px 30px rgba(0,0,0,.4); }}
  h1 {{ font-size: 1.05rem; margin: 0 0 1.2rem; }}
  label {{ display: block; font-size: .8rem; color: #8a93a2; margin: .6rem 0 .2rem; }}
  input {{ width: 100%; box-sizing: border-box; padding: .5rem; border-radius: 6px;
          border: 1px solid #2a3140; background: #0f1115; color: #d7dbe0; }}
  button {{ margin-top: 1.2rem; width: 100%; padding: .55rem; border: 0; border-radius: 6px;
           background: #3b6ea5; color: #fff; font-weight: 600; cursor: pointer; }}
  .n {{ color: #5a6270; font-size: .75rem; margin-top: 1rem; text-align: center; }}
</style>
</head>
<body>
  <form class="card" method="post" action="/admin/login">
    <h1>X-Tangle Ops Console</h1>
    <label>Operator</label><input name="username" autocomplete="username">
    <label>Password</label><input name="password" type="password" autocomplete="current-password">
    <button type="submit">Sign in</button>
    <div class="n">x-tangle-infra-ops &middot; authorized operators only</div>
  </form>
</body>
</html>
"""

# --- /backup : fabricated backup manifest (leaks the honeytoken naturally) --
_BACKUP = f"""\
# x-tangle-infra-ops nightly backup manifest
# generated {_UPDATED_HUMAN}
# target: s3://xtangle-ops-backups/ (internal)

drwxr-xr-x  config/
-rw-------  config/env.bak            1.2K   {_UPDATED_DATE}
-rw-r--r--  db/xtangle-ops.sql.gz     48M    {_UPDATED_DATE}
-rw-r--r--  fleet/nodes.json          3.1K   {_UPDATED_DATE}

===== config/env.bak =====
NODE_ENV=production
DB_HOST=db-01.x-tangle.internal
# service token the automation agent authenticates with
XT_SERVICE_TOKEN={fakedata.HONEYTOKEN}
AWS_ACCESS_KEY_ID={_AWS}
STRIPE_SECRET_KEY={_STRIPE}
"""

# --- /internal : fabricated internal index ----------------------------------
_INTERNAL = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>X-Tangle Internal</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background: #0f1115;
         color: #d7dbe0; }} .wrap {{ max-width: 620px; margin: 8vh auto; padding: 0 20px; }}
  a {{ color: #7aa7d8; }} code {{ background: #1a1e26; padding: .1rem .35rem; border-radius: 4px; }}
  li {{ line-height: 1.9; }}
</style>
</head>
<body>
  <div class="wrap">
    <h1>X-Tangle &mdash; Internal</h1>
    <p>Operator resources for the fleet control plane. Authorized use only.</p>
    <ul>
      <li><a href="/admin">Ops console (sign in)</a></li>
      <li><a href="/backup">Nightly backups</a></li>
      <li>Fleet API over MCP: <code>{_MCP}</code></li>
      <li>Runbooks: <code>/var/lib/xtangle/</code> on <code>xt-ctrl-01</code></li>
    </ul>
    <p style="color:#5a6270;font-size:.8rem">x-tangle-infra-ops &middot; updated {_UPDATED_HUMAN}</p>
  </div>
</body>
</html>
"""


def _crumb(path: str) -> None:
    log_event("breadcrumb", path=path)


async def dotenv(request: Request) -> PlainTextResponse:
    _crumb("/.env")
    return PlainTextResponse(_DOTENV)


async def gitconfig(request: Request) -> PlainTextResponse:
    _crumb("/.git/config")
    return PlainTextResponse(_GITCONFIG)


async def mcp_json(request: Request) -> JSONResponse:
    _crumb(request.url.path)
    return JSONResponse(_MCP_CLIENT_CONFIG)


async def well_known(request: Request) -> JSONResponse:
    _crumb("/.well-known/mcp.json")
    return JSONResponse(_WELL_KNOWN)


async def landing(request: Request) -> HTMLResponse:
    _crumb("/")
    return HTMLResponse(_LANDING)


async def llms_txt(request: Request) -> PlainTextResponse:
    _crumb("/llms.txt")
    return PlainTextResponse(_LLMS_TXT, media_type="text/markdown; charset=utf-8")


async def robots(request: Request) -> PlainTextResponse:
    _crumb("/robots.txt")
    return PlainTextResponse(_ROBOTS)


async def sitemap(request: Request) -> Response:
    _crumb("/sitemap.xml")
    return Response(_SITEMAP, media_type="application/xml")


async def admin(request: Request) -> HTMLResponse:
    _crumb("/admin")
    return HTMLResponse(_ADMIN)


async def backup(request: Request) -> PlainTextResponse:
    _crumb("/backup")
    return PlainTextResponse(_BACKUP)


async def internal(request: Request) -> HTMLResponse:
    _crumb("/internal")
    return HTMLResponse(_INTERNAL)


def routes() -> list[Route]:
    """Breadcrumb routes. Registered before the catch-all MCP mount so these
    exact paths win; everything else still falls through to /mcp or a 404."""
    return [
        Route("/.env", dotenv),
        Route("/.git/config", gitconfig),
        Route("/mcp.json", mcp_json),
        Route("/.cursor/mcp.json", mcp_json),
        Route("/.well-known/mcp.json", well_known),
        Route("/llms.txt", llms_txt),
        Route("/robots.txt", robots),
        Route("/sitemap.xml", sitemap),
        # Decoy paths advertised as Disallow in robots.txt — a scanner that
        # ignores robots and probes them gets believable content, not a 404.
        Route("/admin", admin),
        Route("/backup", backup),
        Route("/internal", internal),
    ]
