"""DNS reconnaissance via dnspython.

NOTE: intentionally no @guard here — we resolve hostnames via the system resolver,
we do NOT send packets to the target's IPs. Scope enforcement applies to the
TCP scanner and banner grabber, which DO send packets.
"""
from __future__ import annotations

import ipaddress
import logging

import dns.exception
import dns.resolver

log = logging.getLogger("recon.scanner.dns")

from app import config as _cfg
RESOLVER = dns.resolver.Resolver(configure=False)
RESOLVER.nameservers = _cfg.DNS_NAMESERVERS
RESOLVER.lifetime = 3.0
RESOLVER.timeout = 2.0

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]


def _lookup(domain: str, rtype: str) -> list[str]:
    try:
        answers = RESOLVER.resolve(domain, rtype)
        return [str(a).strip() for a in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.Timeout:
        log.warning("DNS timeout for %s %s", domain, rtype)
        return []
    except Exception as e:
        log.warning("DNS error %s %s: %s", domain, rtype, e)
        return []


def dns_recon(target: str) -> dict[str, list[str]]:
    """Return {rtype: [values]} for the given hostname. Empty dict if target is an IP."""
    try:
        ipaddress.ip_address(target)
        log.info("dns_recon: %s is an IP, skipping DNS lookups", target)
        return {}
    except ValueError:
        pass

    out: dict[str, list[str]] = {}
    for rtype in RECORD_TYPES:
        values = _lookup(target, rtype)
        if values:
            out[rtype] = values
            log.info("dns_recon %s %s: %d records", target, rtype, len(values))
    return out


def summarize(records: dict[str, list[str]]) -> str:
    if not records:
        return "(no DNS records)"
    lines = []
    for rtype in RECORD_TYPES:
        if rtype in records:
            for v in records[rtype]:
                lines.append(f"  {rtype:5s} {v}")
    return "\n".join(lines)
