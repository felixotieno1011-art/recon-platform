"""Static CVE mapping. Matches open ports to known vulnerabilities."""
from __future__ import annotations

import json
import logging
from pathlib import Path

from app import config

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
        log.info("loaded %d CVE mappings", len(_cache))
    except Exception as e:
        log.error("failed to load CVE map: %s", e)
        _cache = {}
    return _cache


def lookup_cves(port: int) -> list[dict]:
    """Return a list of CVEs for a given port, or [] if none known."""
    cve_map = load_cve_map()
    return cve_map.get(str(port), [])
