# recon-platform

Automated Vulnerability Scanner & Reconnaissance Platform. Built entirely from an Android phone using Termux, Python 3.14, and React.

## ⚠️ Legal Warning
This tool sends network packets. **Only scan hosts you own or have explicit written permission to scan.** The platform enforces a strict `scope.yaml` allowlist; any target not explicitly listed there will be refused.

## Features
- **Async TCP Port Scanner**: Custom `asyncio` implementation with banner grabbing. No `nmap` wrapper.
- **DNS Reconnaissance**: `dnspython` lookups for A, AAAA, MX, TXT, NS, CNAME.
- **arq Task Queue**: Background scanning via Redis and `arq`.
- **Live WebSockets**: Streams progress to the React UI.
- **CVE Mapping**: Enriches open ports with known CVEs via `data/cve_map.json`.
- **JSON Reports**: Downloadable scan reports via `/api/scans/{id}/report`.
- **Termux Native**: Runs completely on Android (no Docker required locally).

## Architecture
- **Backend**: Starlette, plain `uvicorn`, `arq`, `redis`, SQLite (WAL).
- **Frontend**: React + Vite.
- **Legal Gate**: `scope.yaml` + `app/scope_guard.py` (`@guard` decorator).

## Quick Start (Termux)
1. `pkg install redis nodejs-lts`
2. `uv venv .venv && uv pip install -r requirements.txt`
3. `cd frontend && npm install --ignore-scripts && npm run dev` (leave running)
4. `./dev.sh start` (starts Redis, worker, API)
5. Open `http://127.0.0.1:5173`

## Usage
1. Edit `scope.yaml` to add your targets.
2. Enter a target and port range (e.g., `127.0.0.1`, `1-1024`) in the UI.
3. Watch live progress and download the JSON report.

## Docker / CI
Because Docker cannot run in Termux, a GitHub Actions workflow (`.github/workflows/docker.yml`) builds the container image automatically on push.
