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
