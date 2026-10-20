"""Central config. All paths resolve inside the project or $PREFIX. No /tmp, /var, /etc."""
from __future__ import annotations

import os
from pathlib import Path

# Project root = parent of app/
ROOT = Path(__file__).resolve().parent.parent

# --- Filesystem (project-scoped; gitignored) ---
DATA_DIR = ROOT / "data"
LOG_DIR = ROOT / "logs"
DATA_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

DB_PATH = Path(os.environ.get("RECON_DB_PATH", DATA_DIR / "recon.db"))
SCOPE_PATH = Path(os.environ.get("RECON_SCOPE_PATH", ROOT / "scope.yaml"))
LOG_PATH = Path(os.environ.get("RECON_LOG_PATH", LOG_DIR / "recon.log"))

# --- Service ---
HOST = os.environ.get("RECON_HOST", "127.0.0.1")
PORT = int(os.environ.get("RECON_PORT", "8000"))
REDIS_URL = os.environ.get("RECON_REDIS_URL", "redis://127.0.0.1:6379/0")
REDIS_PROGRESS_CHANNEL = "recon:progress"

# --- Scanner defaults ---
DEFAULT_PORT_RANGE = (1, 1024)
SCAN_TIMEOUT = 1.5          # per-port TCP connect timeout (seconds)
SCAN_CONCURRENCY = 256      # asyncio semaphore limit
MAX_PORTS_PER_SCAN = 65535

# --- DNS ---
# Android has no /etc/resolv.conf, so we must feed dnspython explicit nameservers.
# Order: RECON_DNS_NAMESERVERS env (comma-sep) > Android getprop > public fallback.
def _detect_nameservers() -> list[str]:
    env = os.environ.get("RECON_DNS_NAMESERVERS")
    if env:
        return [s.strip() for s in env.split(",") if s.strip()]
    import subprocess
    found: list[str] = []
    for prop in ("net.dns1", "net.dns2", "net.dns3", "net.dns4"):
        try:
            out = subprocess.run(
                ["getprop", prop], capture_output=True, text=True, timeout=1.0
            ).stdout.strip()
            if out:
                found.append(out)
        except Exception:
            pass
    return found or ["1.1.1.1", "8.8.8.8"]


DNS_NAMESERVERS = _detect_nameservers()
