"""WebSocket endpoint streaming scan progress from Redis to the browser."""
from __future__ import annotations

import asyncio
import json
import logging

import redis.asyncio as aioredis
from starlette.websockets import WebSocket, WebSocketDisconnect
from starlette.routing import WebSocketRoute

from app import config, db

log = logging.getLogger("recon.api.ws")


async def _send_snapshot(ws: WebSocket, scan_id: str) -> dict | None:
    scan = db.get_scan(scan_id)
    if scan is None:
        await ws.send_json({"type": "error", "error": "scan not found"})
        return None
    await ws.send_json({"type": "snapshot", "scan": scan})
    return scan


async def scan_ws(ws: WebSocket) -> None:
    scan_id = ws.path_params["scan_id"]
    await ws.accept()

    scan = await _send_snapshot(ws, scan_id)
    if scan is None:
        await ws.close(code=4404)
        return

    if scan["status"] in ("done", "failed"):
        await ws.send_json({"type": "final", "scan": scan,
                            "findings": db.get_findings(scan_id)})
        await ws.close()
        return

    redis_conn = aioredis.from_url(config.REDIS_URL, decode_responses=True)
    pubsub = redis_conn.pubsub()
    await pubsub.subscribe(config.REDIS_PROGRESS_CHANNEL)

    async def _ping_loop():
        while True:
            await asyncio.sleep(30)
            try:
                await ws.send_json({"type": "ping"})
            except Exception:
                return

    ping_task = asyncio.create_task(_ping_loop())
    try:
        async for msg in pubsub.listen():
            if msg.get("type") != "message":
                continue
            try:
                payload = json.loads(msg["data"])
            except Exception:
                continue
            if payload.get("scan_id") != scan_id:
                continue
            await ws.send_json({"type": "progress", "payload": payload})

            row = db.get_scan(scan_id)
            if row and row["status"] in ("done", "failed"):
                await ws.send_json({"type": "final", "scan": row,
                                    "findings": db.get_findings(scan_id)})
                break
    except WebSocketDisconnect:
        log.info("ws client disconnected: scan_id=%s", scan_id)
    except Exception as e:
        log.exception("ws error scan_id=%s: %s", scan_id, e)
    finally:
        ping_task.cancel()
        try:
            await pubsub.unsubscribe(config.REDIS_PROGRESS_CHANNEL)
            await pubsub.aclose()
            await redis_conn.aclose()
        except Exception:
            pass
        try:
            await ws.close()
        except Exception:
            pass


routes = [WebSocketRoute("/ws/scans/{scan_id}", scan_ws)]
