"""Scope guard: the legal gate. No scan runs without passing through here."""
from __future__ import annotations

import asyncio
import functools
import ipaddress
import logging
from pathlib import Path
from typing import Any, Callable

import dns.resolver
import yaml

log = logging.getLogger("recon.scope")

SCOPE_PATH = Path(__file__).resolve().parent.parent / "scope.yaml"


class ScopeViolation(Exception):
    """Raised when a target is not permitted by scope.yaml."""


_cache: dict[str, Any] = {}


def load_scope(path: Path | None = None) -> dict[str, Any]:
    p = path or SCOPE_PATH
    with p.open("r") as f:
        data = yaml.safe_load(f)
    if data.get("mode") != "strict":
        raise RuntimeError(f"Unsupported scope mode: {data.get('mode')!r}")
    _cache["scope"] = data
    log.info("scope loaded from %s (%d allow, %d deny)",
             p, len(data.get("allow", [])), len(data.get("deny", [])))
    return data


def _get_scope() -> dict[str, Any]:
    return _cache.get("scope") or load_scope()


def _parse_entry(entry: str):
    try:
        return ("network", ipaddress.ip_network(entry, strict=False))
    except ValueError:
        return ("host", entry.lower().strip())


def _ip_in_any(ip, entries) -> bool:
    for kind, val in entries:
        if kind == "network" and ip.version == val.version and ip in val:
            return True
    return False


def resolve_target(target: str) -> list[str]:
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass
    answers = dns.resolver.resolve(target, "A", lifetime=5.0)
    ips = [str(a) for a in answers]
    if not ips:
        raise ScopeViolation(f"{target} resolved to zero A records")
    return ips


def check_target(target: str) -> tuple[bool, str, list[str]]:
    scope = _get_scope()
    allow = [_parse_entry(e) for e in scope.get("allow", [])]
    deny = [_parse_entry(e) for e in scope.get("deny", [])]
    require_all = scope.get("require_all_ips_in_scope", True)

    host_lower = target.lower().strip()
    host_allowed = any(k == "host" and v == host_lower for k, v in allow)
    host_denied = any(k == "host" and v == host_lower for k, v in deny)
    if host_denied:
        return False, f"host {target} is explicitly denied", []

    try:
        ips = resolve_target(target)
    except Exception as e:
        return False, f"cannot resolve {target}: {e}", []

    ip_objs = [ipaddress.ip_address(i) for i in ips]
    denied = [str(i) for i in ip_objs if _ip_in_any(i, deny)]
    if denied:
        return False, f"resolved IPs hit deny list: {denied}", ips

    in_scope = [str(i) for i in ip_objs if _ip_in_any(i, allow)]
    out_of_scope = [str(i) for i in ip_objs if str(i) not in in_scope]

    if require_all:
        if out_of_scope:
            return False, f"IPs out of scope: {out_of_scope}", ips
        return True, "all resolved IPs in scope", ips

    if host_allowed or in_scope:
        return True, "at least one IP/host in scope", ips
    return False, f"no IP or host in scope: {ips}", ips


def assert_in_scope(target: str) -> list[str]:
    ok, reason, ips = check_target(target)
    if not ok:
        raise ScopeViolation(f"REFUSED {target}: {reason}")
    log.info("scope OK: %s -> %s (%s)", target, ips, reason)
    return ips


def guard(fn: Callable):
    if not asyncio.iscoroutinefunction(fn):
        @functools.wraps(fn)
        def sync_wrapper(target: str, *a, **kw):
            assert_in_scope(target)
            return fn(target, *a, **kw)
        return sync_wrapper

    @functools.wraps(fn)
    async def async_wrapper(target: str, *a, **kw):
        assert_in_scope(target)
        return await fn(target, *a, **kw)
    return async_wrapper
