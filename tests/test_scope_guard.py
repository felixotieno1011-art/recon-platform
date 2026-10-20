"""Tests for the legal scope gate. These MUST pass before any scan code ships."""
import ipaddress
import pytest

from app import scope_guard
from app.scope_guard import (
    ScopeViolation,
    assert_in_scope,
    check_target,
    guard,
    load_scope,
)


@pytest.fixture(autouse=True)
def _reload_scope():
    scope_guard._cache.clear()
    load_scope()
    yield


def test_loopback_allowed():
    ok, reason, ips = check_target("127.0.0.1")
    assert ok, reason
    assert "127.0.0.1" in ips


def test_private_cidr_allowed():
    ok, reason, ips = check_target("192.168.1.42")
    assert ok, reason


def test_public_ip_out_of_scope_refused():
    ok, reason, _ = check_target("1.2.3.4")
    assert not ok
    assert "out of scope" in reason.lower() or "no ip" in reason.lower()


def test_denylist_hard_block():
    ok, reason, _ = check_target("8.8.8.8")
    assert not ok
    assert "deny" in reason.lower()


def test_assert_in_scope_raises_on_bad_target():
    with pytest.raises(ScopeViolation):
        assert_in_scope("1.2.3.4")


def test_guard_decorator_blocks_sync():
    @guard
    def fake_scan(target):
        return "SHOULD NOT REACH HERE"

    with pytest.raises(ScopeViolation):
        fake_scan("1.2.3.4")


@pytest.mark.asyncio
async def test_guard_decorator_blocks_async():
    @guard
    async def fake_scan(target):
        return "SHOULD NOT REACH HERE"

    with pytest.raises(ScopeViolation):
        await fake_scan("1.2.3.4")


@pytest.mark.asyncio
async def test_guard_decorator_allows_async():
    @guard
    async def fake_scan(target):
        return "scan ran"

    result = await fake_scan("127.0.0.1")
    assert result == "scan ran"


def test_bad_mode_rejected(tmp_path):
    bad = tmp_path / "bad_scope.yaml"
    bad.write_text("mode: loose\nallow: []\ndeny: []\n")
    scope_guard._cache.clear()
    with pytest.raises(RuntimeError, match="Unsupported scope mode"):
        load_scope(bad)
