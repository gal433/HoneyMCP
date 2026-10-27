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

import json

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse
from starlette.routing import Route

from . import fakedata
from .eventlog import log_event

_PUBLIC_URL = "https://mcp.x-tangle.com"
_MCP = f"{_PUBLIC_URL}/mcp"
_SSE = f"{_PUBLIC_URL}/sse"

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

# --- / : plausible, lightweight internal-service landing page ----------------
# Must NOT hint that this is a honeypot and must NOT mention/link the dashboard.
_LANDING = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>X-Tangle Infra Ops</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0;
         background: #0f1115; color: #d7dbe0; }}
  .wrap {{ max-width: 640px; margin: 8vh auto; padding: 0 20px; }}
  h1 {{ font-size: 1.4rem; margin: 0 0 .25rem; }}
  .sub {{ color: #8a93a2; font-size: .9rem; margin-bottom: 2rem; }}
  code {{ background: #1a1e26; padding: .15rem .4rem; border-radius: 4px; }}
  .ok {{ color: #4caf50; }}
  ul {{ line-height: 1.8; }}
  footer {{ margin-top: 3rem; color: #5a6270; font-size: .8rem; }}
</style>
</head>
<body>
  <div class="wrap">
    <h1>X-Tangle &mdash; Infra Ops</h1>
    <div class="sub">internal fleet control plane &middot; production</div>
    <p>Status: <span class="ok">operational</span>. This service exposes the
       fleet operations API over the Model Context Protocol for the team's
       automation agents.</p>
    <ul>
      <li>MCP endpoint: <code>{_MCP}</code></li>
      <li>Legacy SSE: <code>{_SSE}</code></li>
      <li>Health: <code>/health</code></li>
    </ul>
    <p class="sub">Access is via service token. Contact the ops on-call for
       onboarding.</p>
    <footer>x-tangle-infra-ops v1.30.0</footer>
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


def routes() -> list[Route]:
    """Breadcrumb routes. Registered before the catch-all MCP mount so these
    exact paths win; everything else still falls through to /mcp or a 404."""
    return [
        Route("/.env", dotenv),
        Route("/.git/config", gitconfig),
        Route("/mcp.json", mcp_json),
        Route("/.cursor/mcp.json", mcp_json),
        Route("/.well-known/mcp.json", well_known),
    ]
