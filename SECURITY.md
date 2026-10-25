# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.1.x   | ✅        |
| 1.0.x   | ⚠️ (best effort) |
| < 1.0   | ❌        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security problems.**

Please report vulnerabilities by emailing the maintainer or by opening a
[private security advisory](https://github.com/felixotieno1011-art/recon-platform/security/advisories/new).

You can expect:
- Acknowledgment within 72 hours.
- A patch or mitigation plan within 14 days.
- Credit in the release notes (unless you prefer to remain anonymous).

## Scope & Legal Notice

`recon-platform` sends network packets. **Only scan hosts you own or have
explicit written permission to scan.** The platform enforces a strict
`scope.yaml` allowlist; any target not explicitly listed there will be
refused before any packet is sent.

## Out of Scope

- Theoretical attacks requiring physical access to the device running the tool.
- Issues in third-party dependencies (report those upstream — though we
  appreciate a heads-up so we can bump the version).
