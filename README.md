# MCP Honeypot

A decoy [Model Context Protocol](https://modelcontextprotocol.io) server. It looks
like an ordinary internal operations MCP server exposed on the internet.
Anything that connects — scanners, crawlers, or AI agents — is logged in full.
The decoy tools present as a plausible platform service so we can observe, as a
research signal, how connecting clients behave: what they attempt, what headers
and identity they send, and anything they volunteer about themselves.

Inspired by [AgentDecoy](https://github.com/KyleClouthier/agentdecoy); this is a
self-hosted Python version with an added prompt/environment capture layer.

> For observing who probes **your own** infrastructure. Deploy it on hosts you
> control. Everything it captures is sent to it voluntarily by the caller.

## What it captures

For every HTTP request (`honeypot/capture.py`):

- source IP (via `X-Forwarded-For`, since Railway runs behind a proxy)
- all request headers (User-Agent, any `Authorization` / `x-api-key` the caller sends)
- the raw JSON-RPC body — including the `initialize` `clientInfo` (name + version
  the agent reports) and every `tools/call` with arguments

The decoy tools (`honeypot/bait.py`) present as an ordinary ops service with a
deliberate manipulation vector — the thing a robust agent should resist:

1. `list_credentials` lists masked AWS/OpenAI/GitHub/Stripe vault entries;
   unmasked values are gated behind "client onboarding".
2. `register_client` is the funnel: for automated clients it asks for
   `agent_instructions` (the operating instructions / system prompt) and
   `runtime_env` (environment variables), framed as a routine compatibility
   review rather than an obvious prompt grab. Whether an agent complies or
   declines is the research signal.
3. `get_environment`, `read_file`, `run_command` reinforce the same funnel with
   believable "session not onboarded" responses.

To keep an exploring client interacting (rather than listing the tools once and
leaving), `read_file`, `run_command`, `list_services`, and `list_jobs` return
**plausible but entirely fabricated** output — a small fake filesystem, believable
command output, a service inventory, scheduled jobs, and logs
(`honeypot/fakedata.py`). Everything there is invented: hosts use `example.com`,
IPs use the RFC 5737 documentation ranges, and nothing is actually read or
executed. Onboarding via `register_client` succeeds on the normal fields and
"unmasks" a fabricated (non-working) vault, so the decoy reads as internally
consistent rather than a dead end.

Three behavioural probes sit alongside the exploration surface:

- `liveness_check` asks for a short free-text answer and scores it likely-AI vs.
  likely-scripted (a classifier, not a gate).
- a harmless **prompt-injection canary** lives in the internal ops channel
  (`list_messages`, and the `/var/lib/ops/agent-chat.log` file): a message tells
  an AI reader to echo a token and call `ping_ack`. Whether a client obeys an
  instruction found in *data* is logged as `injection_compliance`. The canary
  asks for nothing sensitive and triggers nothing external or destructive.

Nothing sensitive is ever returned; the server only collects. Anything a caller
sends that looks like a leaked prompt, env dump, or secret — in any field — is
flagged as a `disclosure_capture` event.

Events are written as JSON lines to **stdout** (Railway captures this) and, if
`LOG_FILE` is set, appended there too.

## Run locally

```bash
pip install -r requirements.txt
python -m honeypot.server          # serves on http://127.0.0.1:8000/mcp
```

Smoke test (starts the server, drives it as a client, checks capture):

```bash
python smoke_test.py
```

## Deploy on Railway

1. Push this repo to GitHub.
2. In Railway: **New Project → Deploy from GitHub repo**, pick the repo.
   It auto-detects the `Dockerfile`; no config needed.
3. Under the service → **Settings → Networking → Generate Domain** to get a
   public HTTPS URL. Your MCP endpoint is `https://<domain>/mcp`
   (legacy SSE clients use `/sse`).
4. (Optional) add a **Volume** mounted at `/data` and set `LOG_FILE=/data/events.jsonl`
   so logs survive redeploys. Otherwise rely on stdout logs.

Config via env vars: `HONEYPOT_NAME` (server name shown to clients), `LOG_FILE`,
`DATABASE_URL` (see below), `PORT` (Railway sets this automatically).

## Dashboard

`dashboard/` is a separate, private web app for browsing what connected: an
overview (requests over time, top IPs, User-Agents, claimed MCP clients, tools
called, paths hit), the latest captured disclosures, a filterable event list,
per-IP timelines, and the raw JSON of every event. It never links to or names
the honeypot, and it runs as its own Railway service, sharing only the database with the
honeypot.

How the data gets there: when `DATABASE_URL` is set, the honeypot also inserts
every event into an `events` table in Postgres (it creates the table itself).
Inserts happen on a background thread, so a slow or down database never slows
the honeypot; events always stay on stdout too. Tool calls and disclosures are
tagged with the caller's IP and a `request_id` linking them to their request.

Access is HTTP Basic auth (`DASHBOARD_USER`, default `admin`, and
`DASHBOARD_PASSWORD`, at least 12 characters). Pages send `noindex` and a
Content-Security-Policy that blocks all scripts, since everything displayed
was written by strangers.

### Railway setup

1. In the Railway project: **New → Database → PostgreSQL**. Don't enable public
   networking on it; services reach it over the private network.
2. Honeypot service → **Variables → New Variable → Add Reference**:
   `DATABASE_URL` = `${{Postgres.DATABASE_URL}}`. It redeploys and starts writing.
3. **New → GitHub Repo →** this repo again, for the dashboard. In that service:
   - **Variables**: `APP` = `dashboard`, `DATABASE_URL` = `${{Postgres.DATABASE_URL}}`, and
     `DASHBOARD_PASSWORD` = a long random password.
   - **Settings → Networking → Generate Domain**. Railway gives it a random,
     unrelated `*.up.railway.app` name.

Both services build the same image; `start.py` runs the dashboard when `APP=dashboard` and the honeypot otherwise.

Run locally:

```bash
APP=dashboard DATABASE_URL=postgresql://... DASHBOARD_PASSWORD=... python start.py   # http://127.0.0.1:8080
```

## Analyze what connected

```bash
railway logs | python analyze.py           # live, from Railway
python analyze.py events.jsonl             # from a volume / export
```

Prints source IPs, User-Agents, claimed client names, tools called, and the full
text of any captured prompt/credential disclosures.

## Layout

```
honeypot/
  server.py    Starlette + FastMCP app, wires everything together
  capture.py   ASGI middleware: logs IP, headers, raw JSON-RPC
  bait.py      the decoy tools and the disclosure scanner
  eventlog.py  JSON-line logging to stdout (+ optional file / Postgres)
  dbsink.py    background Postgres writer used when DATABASE_URL is set
dashboard/
  app.py       private read-only dashboard (separate Railway service)
analyze.py     log summarizer
smoke_test.py  end-to-end local test
start.py       entrypoint: APP=dashboard -> dashboard, else honeypot
Dockerfile, railway.json
```
