"""Tests for the async TCP scanner and DNS recon."""
import asyncio

import pytest

from app import scope_guard
from app.scanner.tcp import _probe_one, parse_ports, scan_ports
from app.scanner.dns_recon import dns_recon


@pytest.fixture(autouse=True)
def _reload_scope():
    scope_guard._cache.clear()
    scope_guard.load_scope()
    yield


def test_parse_ports_mixed():
    assert parse_ports("22,80,443") == [22, 80, 443]
    assert parse_ports("22-25") == [22, 23, 24, 25]
    assert parse_ports("1-3,10") == [1, 2, 3, 10]


def test_parse_ports_rejects_bad():
    with pytest.raises(ValueError):
        parse_ports("0")
    with pytest.raises(ValueError):
        parse_ports("70000")
    with pytest.raises(ValueError):
        parse_ports("80-22")


@pytest.mark.asyncio
async def test_scan_finds_local_listener():
    async def _handle(r, w):
        w.close()

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        results = await scan_ports("127.0.0.1", ["127.0.0.1"], [port], progress_cb=None)
    finally:
        server.close()
        await server.wait_closed()
    assert len(results) == 1
    assert results[0].port == port
    assert results[0].open is True


@pytest.mark.asyncio
async def test_scan_reports_closed_port():
    # find a port nothing is listening on (close a test server first)
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    await asyncio.sleep(0.05)
    res = await _probe_one("127.0.0.1", port, timeout=0.5)
    assert res.open is False


@pytest.mark.asyncio
async def test_scan_refuses_out_of_scope():
    with pytest.raises(scope_guard.ScopeViolation):
        await scan_ports("1.2.3.4", ["1.2.3.4"], [80])


def test_dns_recon_skips_ip():
    assert dns_recon("127.0.0.1") == {}


def test_dns_recon_returns_dict_for_hostname():
    result = dns_recon("scanme.nmap.org")
    assert isinstance(result, dict)
    # Do not assert specific records — network may vary. Just shape.
    for k, v in result.items():
        assert isinstance(k, str)
        assert isinstance(v, list)
