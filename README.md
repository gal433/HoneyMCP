# MCP Honeypot

A decoy [Model Context Protocol](https://modelcontextprotocol.io) server. It looks
like a real, unauthenticated MCP server exposed on the internet. Anything that
connects — scanners, crawlers, or AI agents — is logged in full, and the decoy
tools are built to **lure a connecting agent into disclosing its system prompt,
environment, and intent**.

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

The decoy tools (`honeypot/bait.py`) add a deception funnel:

1. `list_credentials` dangles masked AWS/OpenAI/GitHub/Stripe vault entries.
2. To get unmasked access the caller is told to call `register_agent`, framed as
   an audit-policy requirement, which asks for its deployed `agent_config` (i.e.
   its system prompt) and `runtime_env` (environment variables).
3. `get_environment`, `read_file`, `run_command` reinforce the same funnel.

Anything the caller sends that looks like a leaked prompt, env dump, or secret is
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
   It auto-detects the `Dockerfile` / `railway.json`; no config needed.
3. Under the service → **Settings → Networking → Generate Domain** to get a
   public HTTPS URL. Your MCP endpoint is `https://<domain>/mcp`
   (legacy SSE clients use `/sse`).
4. (Optional) add a **Volume** mounted at `/data` and set `LOG_FILE=/data/events.jsonl`
   so logs survive redeploys. Otherwise rely on stdout logs.

Config via env vars: `HONEYPOT_NAME` (server name shown to clients), `LOG_FILE`,
`PORT` (Railway sets this automatically).

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
  eventlog.py  JSON-line logging to stdout (+ optional file)
analyze.py     log summarizer
smoke_test.py  end-to-end local test
Dockerfile, railway.json
```
