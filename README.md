# recon-platform

[![CI](https://github.com/felixotieno1011-art/recon-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/felixotieno1011-art/recon-platform/actions/workflows/ci.yml)
[![Security Scan](https://github.com/felixotieno1011-art/recon-platform/actions/workflows/security.yml/badge.svg)](https://github.com/felixotieno1011-art/recon-platform/actions/workflows/security.yml)
![Tests](https://img.shields.io/badge/tests-24%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.14-blue)
![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Linux-lightgrey)

Automated Vulnerability Scanner & Reconnaissance Platform. Built end-to-end on an
Android phone using Termux (aarch64, Python 3.14), Starlette, Redis, `arq`,
SQLite, and React + Vite.

## ⚠️ Legal Notice

This tool sends network packets. **Only scan hosts you own or have explicit
written permission to scan.** The platform enforces a strict `scope.yaml`
allowlist; any target not explicitly listed there will be refused before a
single packet is sent.

See [SECURITY.md](SECURITY.md) for vulnerability disclosure.

## Why this exists

Most "port scanner" demos equate an open port with a vulnerability. This
platform distinguishes **evidence** from **guesswork**:

- TCP port is open → finding recorded.
- Banner matched a known product → CVE candidates ranked with `confidence: high`.
- Version compared against a known affected range → CVE is only reported if
  the version is actually in range.
- No banner / no match → CVE candidates are marked `confidence: low` with the
  reason `"port heuristic only — service not fingerprinted"`.

This design is the direct outcome of a code review that asked for
**target authorization reliability, API access control, and honest CVE
reporting**. Every item was addressed in
[`v1.1.0`](https://github.com/felixotieno1011-art/recon-platform/releases/tag/v1.1.0).

## Features

- **Async TCP port scanner** — custom `asyncio.open_connection`, concurrency-limited, banner-grabbing. No `nmap` wrapper.
- **Service fingerprinting** — parses SSH / HTTP / FTP banners into `{product, version}`.
- **Honest CVE matching** — CVE candidates carry `confidence` + `reason`. Version-range aware.
- **DNS reconnaissance** — A, AAAA, MX, TXT, NS, CNAME via `dnspython`.
- **arq task queue** — Redis-backed background scanning with progress events.
- **Live WebSockets** — streams progress to the browser.
- **Bearer-token API auth** — state-changing endpoints require a token; token is generated on first run and stored at `data/.api_token` (mode 600).
- **DNS-rebinding safe** — the worker scans the exact IPs vetted at enqueue time; no re-resolution.
- **Multi-IP scanning** — all approved resolved IPs are scanned concurrently; results are tagged by IP.
- **JSON report export** — `/api/scans/{id}/report`.
- **Termux native** — runs entirely on Android. Docker only in CI.

## Architecture

## Architecture

```

┌───────────────┐   POST /api/scans    ┌──────────────────┐
│  React UI     │ ───────────────────► │  Starlette API   │
│  (Vite)       │ ◄──── WebSocket ──── │  (uvicorn)       │
└───────┬───────┘   progress + final   └────┬─────────────┘
│                                   │
│                    SQLite (WAL)   │  arq enqueue
│                                   ▼
│                          ┌──────────────────┐
│                          │  Redis           │
│                          │  queue + pubsub  │
│                          └────────┬─────────┘
│                                   │
│                          ┌────────▼─────────┐
│                          │  arq worker      │
│                          │  (jobs.py)       │
│                          └────────┬─────────┘
│                                   │
│                          ┌────────▼─────────┐
│                          │  scanner/        │
│                          │  tcp.py +        │
│                          │  dns_recon.py +  │
│                          │  fingerprint.py  │
│                          └──────────────────┘

```

**Legal gate:** every scan entry point wears `@guard` from
`app/scope_guard.py`; the scanner re-validates each IP before connecting.

## Quick Start (Termux)

```bash
pkg install -y redis nodejs-lts tmux
git clone https://github.com/felixotieno1011-art/recon-platform.git
cd recon-platform
uv venv .venv && uv pip install -r requirements.txt
cd frontend && npm install --ignore-scripts && cd ..

# Edit scope.yaml to add your targets
nano scope.yaml

# Start backend (Redis + arq worker + API)
./dev.sh start

# In another pane: start frontend
cd frontend && npm run dev
```

Open http://127.0.0.1:5173/. First-run will prompt for the API token,
which is printed by:

```bash
.venv/bin/python -c "from app import config; print(config.API_TOKEN)"
```

Running tests

```bash
.venv/bin/python -m pytest tests/ -v
```

24 tests covering the scope gate, scanner, CVE matcher, and API.

Project layout

```
app/
  main.py             Starlette app
  config.py           paths, redis, DNS, API token
  db.py               SQLite WAL, scans + findings
  scope_guard.py      the legal gate (@guard)
  cve.py              honest CVE matching
  cve_map.json        curated CVE database
  fingerprint.py      banner → {product, version}
  scanner/
    tcp.py            async port scanner
    dns_recon.py      dnspython lookups
  api/
    routes.py         REST endpoints
    ws.py             WebSocket streaming
    auth.py           bearer-token auth
  worker/
    arq_settings.py   arq WorkerSettings
    jobs.py           run_scan job
frontend/
  src/                React UI
tests/                pytest suite
dev.sh                service manager (start / stop / status / logs)
```

License

MIT

```

---
