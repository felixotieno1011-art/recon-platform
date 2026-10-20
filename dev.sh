#!/data/data/com.termux/files/usr/bin/bash
# dev.sh — manage recon-platform services on Termux
# Usage: ./dev.sh {start|stop|status|logs}
set -u

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

PID_DIR="$ROOT/.pids"
LOG_DIR="$ROOT/logs"
mkdir -p "$PID_DIR" "$LOG_DIR"

REDIS_PID="$PID_DIR/redis.pid"
WORKER_PID="$PID_DIR/worker.pid"
API_PID="$PID_DIR/api.pid"

PY="$ROOT/.venv/bin/python"

alive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

start_redis() {
    if alive "$REDIS_PID"; then echo "[redis] already running"; return; fi
    redis-server --daemonize yes --pidfile "$REDIS_PID" --logfile "$LOG_DIR/redis.log"
    sleep 0.5
    alive "$REDIS_PID" && echo "[redis] started pid=$(cat "$REDIS_PID")" || echo "[redis] FAILED — see $LOG_DIR/redis.log"
}

start_worker() {
    if [ ! -f app/worker/arq_settings.py ]; then
        echo "[worker] skipped — app/worker/arq_settings.py not written yet (Day 4)"
        return
    fi
    if alive "$WORKER_PID"; then echo "[worker] already running"; return; fi
    nohup "$PY" -m arq app.worker.arq_settings.WorkerSettings \
        > "$LOG_DIR/worker.log" 2>&1 &
    echo $! > "$WORKER_PID"
    sleep 0.5
    alive "$WORKER_PID" && echo "[worker] started pid=$(cat "$WORKER_PID")" || echo "[worker] FAILED — see $LOG_DIR/worker.log"
}

start_api() {
    if alive "$API_PID"; then echo "[api] already running on :8000"; return; fi
    "$PY" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 &
    echo $! > "$API_PID"
}

stop_all() {
    for f in "$API_PID" "$WORKER_PID"; do
        if alive "$f"; then kill "$(cat "$f")" 2>/dev/null && echo "[stop] $(basename "$f" .pid)"; fi
        rm -f "$f"
    done
    if alive "$REDIS_PID"; then
        redis-cli shutdown nosave 2>/dev/null
        rm -f "$REDIS_PID"
        echo "[stop] redis"
    fi
    termux-wake-unlock 2>/dev/null || true
}

status_all() {
    for pair in "redis:$REDIS_PID" "worker:$WORKER_PID" "api:$API_PID"; do
        name="${pair%%:*}"; file="${pair##*:}"
        if alive "$file"; then echo "  $name: UP (pid $(cat "$file"))"; else echo "  $name: down"; fi
    done
}

case "${1:-start}" in
    start)
        termux-wake-lock 2>/dev/null || true
        start_redis
        start_worker
        echo "[api] starting on http://127.0.0.1:8000 (Ctrl+C to stop API)"
        start_api
        wait "$(cat "$API_PID")" 2>/dev/null
        ;;
    stop)   stop_all ;;
    status) status_all ;;
    logs)   tail -n 40 "$LOG_DIR/worker.log" ;;
    *)      echo "usage: $0 {start|stop|status|logs}"; exit 1 ;;
esac
