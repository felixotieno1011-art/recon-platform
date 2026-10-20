"""Async TCP port scanner. Every public entry wears @guard."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass

from app import config
from app.scope_guard import guard

log = logging.getLogger("recon.scanner.tcp")


@dataclass
class PortResult:
    port: int
    open: bool
    banner: str | None = None


async def _probe_one(ip: str, port: int, timeout: float) -> PortResult:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return PortResult(port=port, open=False)

    banner = None
    try:
        banner_bytes = await asyncio.wait_for(reader.read(256), timeout=0.6)
        if banner_bytes:
            banner = banner_bytes.decode("utf-8", errors="replace").strip()
    except (asyncio.TimeoutError, OSError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return PortResult(port=port, open=True, banner=banner)


def parse_ports(spec: str) -> list[int]:
    """Accept '1-1024', '22,80,443', or '22-25,80,443'. Returns sorted unique ports."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo_i, hi_i = int(lo), int(hi)
            if lo_i < 1 or hi_i > 65535 or lo_i > hi_i:
                raise ValueError(f"bad range: {part}")
            ports.update(range(lo_i, hi_i + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"bad port: {p}")
            ports.add(p)
    if len(ports) > config.MAX_PORTS_PER_SCAN:
        raise ValueError(f"too many ports: {len(ports)} > {config.MAX_PORTS_PER_SCAN}")
    return sorted(ports)


@guard
async def scan_ports(
    target: str,
    ports: list[int],
    *,
    progress_cb=None,
) -> list[PortResult]:
    """Scan `ports` on `target`. Refuses if target is out of scope (raises ScopeViolation)."""
    from app.scope_guard import resolve_target
    ip = resolve_target(target)[0]           # guard already validated; use first IP
    sem = asyncio.Semaphore(config.SCAN_CONCURRENCY)
    results: list[PortResult] = []
    done = 0
    total = len(ports)

    async def _wrapped(port: int) -> None:
        nonlocal done
        async with sem:
            res = await _probe_one(ip, port, config.SCAN_TIMEOUT)
            results.append(res)
        done += 1
        if progress_cb and (done % 50 == 0 or done == total):
            progress_cb(done, total)

    log.info("scan %s (%s): %d ports", target, ip, total)
    await asyncio.gather(*(_wrapped(p) for p in ports))
    results.sort(key=lambda r: r.port)
    open_count = sum(1 for r in results if r.open)
    log.info("scan %s done: %d/%d open", target, open_count, total)
    return results


def to_dicts(results: list[PortResult]) -> list[dict]:
    return [asdict(r) for r in results]
