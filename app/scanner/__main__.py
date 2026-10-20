"""CLI: python -m app.scanner <target> [--ports 1-1024] [--timeout 1.5]"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from app import config
from app.scanner.tcp import parse_ports, scan_ports


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _progress(done: int, total: int) -> None:
    pct = int(done * 100 / total) if total else 100
    bar = "#" * (pct // 5) + "." * (20 - pct // 5)
    print(f"\r  [{bar}] {done}/{total} ({pct}%)", end="", flush=True)
    if done == total:
        print()


async def _amain(args: argparse.Namespace) -> int:
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"bad --ports: {e}", file=sys.stderr)
        return 2

    if args.timeout:
        config.SCAN_TIMEOUT = args.timeout

    try:
        results = await scan_ports(args.target, ports, progress_cb=_progress)
    except Exception as e:
        print(f"scan aborted: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    open_ports = [r for r in results if r.open]
    print(f"\n{len(open_ports)} open / {len(results)} scanned on {args.target}")
    for r in open_ports:
        banner = f"  {r.banner[:60]!r}" if r.banner else ""
        print(f"  {r.port:5d}/tcp open{banner}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="app.scanner")
    p.add_argument("target")
    p.add_argument("--ports", default="1-1024")
    p.add_argument("--timeout", type=float, default=config.SCAN_TIMEOUT)
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()
    _setup_logging(args.verbose)
    return asyncio.run(_amain(args))


if __name__ == "__main__":
    sys.exit(main())
