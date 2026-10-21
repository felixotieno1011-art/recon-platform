"""REST API routes for recon-platform."""
from __future__ import annotations

import json
import time
import logging
import sys

from arq import create_pool
from arq.connections import RedisSettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from app import config, db
from app.api.auth import require_auth
from app.scope_guard import ScopeViolation, assert_in_scope
from app.scanner.tcp import parse_ports

log = logging.getLogger("recon.api.routes")


async def _enqueue(scan_id: str, ports: str) -> bool:
    try:
        pool = await create_pool(RedisSettings.from_dsn(config.REDIS_URL))
        await pool.enqueue_job("run_scan", scan_id, ports)
        await pool.aclose()
        return True
    except Exception as e:
        log.error("enqueue failed for %s: %s", scan_id, e)
        return False


@require_auth
async def submit_scan(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON body"}, status_code=400)
    target = (body.get("target") or "").strip()
    ports = str(body.get("ports") or "1-1024")
    if not target:
        return JSONResponse({"error": "target required"}, status_code=400)

    try:
        parse_ports(ports)
    except ValueError as e:
        return JSONResponse({"error": f"invalid ports: {e}"}, status_code=400)

    try:
        resolved = assert_in_scope(target)
    except ScopeViolation as e:
        return JSONResponse({"error": str(e), "target": target}, status_code=403)
    except Exception as e:
        return JSONResponse({"error": f"resolution failed: {e}"}, status_code=400)

    scan_id = db.new_scan(target, resolved)
    ok = await _enqueue(scan_id, ports)
    if not ok:
        db.update_scan(scan_id, status="failed", error="enqueue failed")
        return JSONResponse({"error": "queue unavailable", "scan_id": scan_id}, status_code=503)
    return JSONResponse({
        "scan_id": scan_id,
        "target": target,
        "resolved_ips": resolved,
        "ports": ports,
        "status": "queued",
    }, status_code=202)


async def list_scans(request: Request) -> JSONResponse:
    return JSONResponse({"scans": db.list_scans(limit=50)})


async def get_scan(request: Request) -> JSONResponse:
    scan_id = request.path_params["scan_id"]
    row = db.get_scan(scan_id)
    if row is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"scan": row, "findings": db.get_findings(scan_id)})


async def healthz(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})



async def scan_report(request: Request) -> JSONResponse:
    scan_id = request.path_params["scan_id"]
    row = db.get_scan(scan_id)
    if row is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    
    findings = db.get_findings(scan_id)
    cve_count = sum(len(f["data"].get("cve_candidates", [])) for f in findings if f["kind"] == "port")
    
    report = {
        "generated_at": time.time(),
        "scan": row,
        "summary": {
            "open_ports": sum(1 for f in findings if f["kind"] == "port"),
            "dns_records": sum(1 for f in findings if f["kind"] == "dns"),
            "cves": cve_count
        },
        "findings": findings
    }
    return JSONResponse(report)

routes = [
    Route("/healthz", healthz, methods=["GET"]),
    Route("/api/scans", submit_scan, methods=["POST"]),
    Route("/api/scans", list_scans, methods=["GET"]),
    Route("/api/scans/{scan_id}", get_scan, methods=["GET"]),
    Route("/api/scans/{scan_id}/report", scan_report, methods=["GET"]),
]
