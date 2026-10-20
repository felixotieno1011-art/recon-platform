"""CLI to enqueue a scan: python -m app.worker <target> [--ports 1-1024] [--wait]"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time

from arq import create_pool
from arq.connections import RedisSettings

from app import config, db
from app.scope_guard import ScopeViolation, assert_in_scope


async def _amain(args: argparse.Namespace) -> int:
    db.init_db()

    # 1. Legal gate at enqueue time — before touching Redis or DB
    try:
        resolved = assert_in_scope(args.target)
    except ScopeViolation as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 2

    # 2. Persist scan row (queued)
    scan_id = db.new_scan(args.target, resolved)
    print(f"scan_id={scan_id} target={args.target} ports={args.ports}")

    # 3. Enqueue job in arq
    redis_settings = RedisSettings.from_dsn(config.REDIS_URL)
    pool = await create_pool(redis_settings)
    await pool.enqueue_job("run_scan", scan_id, args.ports)
    await pool.aclose()
    print(f"enqueued → arq (job 'run_scan' scan_id={scan_id})")

    if not args.wait:
        return 0

    # 4. Poll SQLite until done
    print("waiting for worker...", end="", flush=True)
    deadline = time.time() + args.timeout
    last_status = None
    while time.time() < deadline:
        row = db.get_scan(scan_id)
        if row is None:
            print(" lost scan row"); return 1
        if row["status"] != last_status:
            print(f"\n  status={row['status']} progress={row['progress']}%", end="", flush=True)
            last_status = row["status"]
        if row["status"] in ("done", "failed"):
            break
        await asyncio.sleep(1.0)
    else:
        print(" TIMEOUT"); return 1

    row = db.get_scan(scan_id)
    findings = db.get_findings(scan_id)
    print()
    print(f"final: status={row['status']} findings={len(findings)}")
    if row["error"]:
        print(f"error: {row['error']}")
    for f in findings:
        if f["kind"] == "port":
            b = f["data"].get("banner")
            suffix = f"  {b[:40]!r}" if b else ""
            print(f"  port {f['data']['port']}/tcp open{suffix}")
        elif f["kind"] == "dns":
            for rtype, values in f["data"].items():
                print(f"  dns {rtype}: {len(values)} record(s)")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="app.worker")
    p.add_argument("target")
    p.add_argument("--ports", default="1-1024")
    p.add_argument("--wait", action="store_true", help="wait for completion and print findings")
    p.add_argument("--timeout", type=int, default=120)
    args = p.parse_args()
    return asyncio.run(_amain(args))


if __name__ == "__main__":
    sys.exit(main())
