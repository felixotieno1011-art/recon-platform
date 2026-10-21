"""Async TCP port scanner. Scans pre-resolved IPs, which the caller MUST verify first."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass

from app import config

log = logging.getLogger("recon.scanner.tcp")


@dataclass
class PortResult:
    ip: str
    port: int
    open: bool
    banner: str | None = None


async def _probe_one(ip: str, port: int, timeout: float) -> PortResult:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return PortResult(ip=ip, port=port, open=False)

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
    return PortResult(ip=ip, port=port, open=True, banner=banner)


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


async def scan_ports(
    target: str,
    ip_list: list[str],
    ports: list[int],
    *,
    progress_cb=None,
) -> list[PortResult]:
    """Scan ports on the given IPs. Caller MUST verify scope BEFORE calling this."""
    from app.scope_guard import check_target, ScopeViolation

    # Defense-in-depth: re-verify every IP just in case a rogue caller bypasses the API
    for ip in ip_list:
        ok, reason, _ = check_target(ip)
        if not ok:
            raise ScopeViolation(f"REFUSED {ip}: {reason}")

    sem = asyncio.Semaphore(config.SCAN_CONCURRENCY)
    results: list[PortResult] = []
    done = 0
    total = len(ip_list) * len(ports)

    async def _wrapped(ip: str, port: int) -> None:
        nonlocal done
        async with sem:
            res = await _probe_one(ip, port, config.SCAN_TIMEOUT)
            if res.open:
                results.append(res)
        done += 1
        if progress_cb and (done % 50 == 0 or done == total):
            progress_cb(done, total)

    log.info("scan %s: %d IPs, %d ports (%d checks)",
             target, len(ip_list), len(ports), total)
    tasks = [_wrapped(ip, p) for ip in ip_list for p in ports]
    await asyncio.gather(*tasks)
    results.sort(key=lambda r: (r.ip, r.port))
    log.info("scan %s done: %d open", target, len(results))
    return results


def to_dicts(results: list[PortResult]) -> list[dict]:
    return [asdict(r) for r in results]
