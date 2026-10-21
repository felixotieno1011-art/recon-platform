"""Extracts product/version from service banners."""
from __future__ import annotations

import re

# Common service fingerprints
PATTERNS = [
    (re.compile(r"SSH-[\d.]+-OpenSSH_([\d.p]+)", re.I), "openssh"),
    (re.compile(r"SSH-[\d.]+-Dropbear_([\d.]+)", re.I), "dropbear"),
    (re.compile(r"Server: Apache/([\d.]+)", re.I), "apache"),
    (re.compile(r"Server: nginx/([\d.]+)", re.I), "nginx"),
    (re.compile(r"Microsoft-IIS/([\d.]+)", re.I), "iis"),
    (re.compile(r"ProFTPD ([\d.]+)", re.I), "proftpd"),
    (re.compile(r"vsFTPd ([\d.]+)", re.I), "vsftpd"),
]


def parse_banner(banner: str | None) -> dict | None:
    """Return {'product': str, 'version': str} if a known banner is matched, else None."""
    if not banner:
        return None
        
    for pattern, product in PATTERNS:
        match = pattern.search(banner)
        if match:
            return {"product": product, "version": match.group(1)}
            
    return None
