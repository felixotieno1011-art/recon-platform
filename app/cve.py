"""Honest CVE matching. Distinguishes confirmed (fingerprinted) from heuristic (port-only) findings."""
from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger("recon.cve")

CVE_MAP_PATH = Path(__file__).resolve().parent / "cve_map.json"
_cache: dict = {}


def load_cve_map() -> dict:
    global _cache
    if _cache:
        return _cache
    try:
        with open(CVE_MAP_PATH) as f:
            _cache = json.load(f)
        log.info("loaded CVE map: %d products, %d ports",
                 len(_cache.get("products", {})), len(_cache.get("ports", {})))
    except Exception as e:
        log.error("failed to load CVE map: %s", e)
        _cache = {"products": {}, "ports": {}}
    return _cache


def _version_lt(a: str, b: str) -> bool:
    """Best-effort numeric version comparison. Returns True if a < b."""
    def _tuple(v):
        parts = []
        for x in v.replace("p", ".").split("."):
            try:
                parts.append(int("".join(ch for ch in x if ch.isdigit()) or 0))
            except Exception:
                parts.append(0)
        return tuple(parts)
    try:
        return _tuple(a) < _tuple(b)
    except Exception:
        return False


def lookup_cves(port: int, fingerprint: dict | None = None) -> list[dict]:
    """Return CVE candidates. Fingerprinted matches are 'medium'/'high' confidence;
    port-only matches are 'low' confidence with an explicit reason."""
    cve_map = load_cve_map()
    products = cve_map.get("products", {})
    ports_map = cve_map.get("ports", {})
    out: dict[str, dict] = {}   # key by CVE id, merge confidence

    # 1. Fingerprint-based (higher confidence)
    if fingerprint and fingerprint.get("product"):
        product = fingerprint["product"].lower()
        version = fingerprint.get("version", "")
        for cve in products.get(product, []):
            affected = cve.get("affected", "")
            # Compare version if we can
            if affected.startswith("<") and version:
                if _version_lt(version, affected[1:]):
                    confidence = "high"
                    reason = f"{product} {version} < {affected[1:]}"
                else:
                    continue   # version not affected — skip
            else:
                confidence = "medium"
                reason = f"{product} {version or 'version unknown'} — affected range: {affected or 'all'}"
            out[cve["id"]] = {**cve, "confidence": confidence, "reason": reason}

    # 2. Port-based heuristic (lower confidence) — only add if not already present
    for cve in ports_map.get(str(port), []):
        if cve["id"] not in out:
            out[cve["id"]] = {
                **cve,
                "confidence": "low",
                "reason": "port heuristic only — service not fingerprinted",
            }

    return list(out.values())
