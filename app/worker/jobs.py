"""arq job functions. Each job assumes its scan row already exists in SQLite."""
from __future__ import annotations

import asyncio
import json
import logging

import redis.asyncio as aioredis
from arq import create_pool
from arq.connections import RedisSettings

from app import config, db
from app.scanner.dns_recon import dns_recon
from app.scanner.tcp import parse_ports, scan_ports, to_dicts

log = logging.getLogger("recon.worker.jobs")


async def _publish_progress(r: aioredis.Redis | None, scan_id: str, done: int, total: int) -> None:
    if r is None:
        return
    try:
        payload = json.dumps({"scan_id": scan_id, "done": done, "total": total})
        await r.publish(config.REDIS_PROGRESS_CHANNEL, payload)
    except Exception as e:
        log.debug("progress publish failed (non-fatal): %s", e)


async def run_scan(ctx, scan_id: str, port_spec: str = "1-1024") -> dict:
    """Job entrypoint. Loads scan row, runs recon + scan, writes findings."""
    scan = db.get_scan(scan_id)
    if scan is None:
        log.warning("run_scan: scan %s not found; skipping", scan_id)
        return {"scan_id": scan_id, "status": "missing"}

    target = scan["target"]
    log.info("run_scan %s target=%s ports=%s", scan_id, target, port_spec)
    db.update_scan(scan_id, status="running")

    redis_conn = ctx.get("redis") if ctx else None
    if redis_conn is None:
        try:
            redis_conn = aioredis.from_url(config.REDIS_URL, decode_responses=True)
        except Exception as e:
            log.warning("no redis for progress: %s", e)
            redis_conn = None

    try:
        # 1. DNS recon (fast, no @guard — pure resolution)
        dns = dns_recon(target)
        if dns:
            db.add_finding(scan_id, "dns", dns)

        # 2. TCP scan
        ports = parse_ports(port_spec)
        loop = asyncio.get_running_loop()

        def progress_cb(done: int, total: int) -> None:
            pct = int(done * 100 / total) if total else 100
            db.update_scan(scan_id, progress=pct)
            asyncio.create_task(_publish_progress(redis_conn, scan_id, done, total))

        results = await scan_ports(target, ports, progress_cb=progress_cb)

        # 3. Persist each open port as a finding
        for r in to_dicts(results):
            if r["open"]:
                db.add_finding(scan_id, "port", r)

        db.update_scan(scan_id, status="done", progress=100)
        open_count = sum(1 for r in results if r.open)
        log.info("run_scan %s done: %d open", scan_id, open_count)
        return {"scan_id": scan_id, "status": "done", "open_ports": open_count}

    except Exception as e:
        log.exception("run_scan %s failed", scan_id)
        db.update_scan(scan_id, status="failed", error=f"{type(e).__name__}: {e}")
        raise
    finally:
        if redis_conn is not None and ctx is None:
            await redis_conn.close()
