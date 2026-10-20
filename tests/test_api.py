"""API tests via httpx ASGITransport (no real network)."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import pytest_asyncio

from app import config, db, scope_guard
from app.main import app


@pytest_asyncio.fixture
async def client(tmp_path: Path, monkeypatch):
    test_db = tmp_path / "test.db"
    monkeypatch.setattr(config, "DB_PATH", test_db)
    db.init_db(test_db)
    scope_guard._cache.clear()
    scope_guard.load_scope()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_healthz(client):
    r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_submit_scan_loopback(client):
    r = await client.post("/api/scans", json={"target": "127.0.0.1", "ports": "80"})
    assert r.status_code in (202, 503)
    body = r.json()
    assert "scan_id" in body
    assert body["target"] == "127.0.0.1"


@pytest.mark.asyncio
async def test_submit_out_of_scope(client):
    r = await client.post("/api/scans", json={"target": "1.2.3.4", "ports": "80"})
    assert r.status_code == 403
    assert "out of scope" in r.json()["error"].lower()


@pytest.mark.asyncio
async def test_missing_target(client):
    r = await client.post("/api/scans", json={"ports": "80"})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_get_scan_not_found(client):
    r = await client.get("/api/scans/deadbeef")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_list_scans_shape(client):
    r = await client.get("/api/scans")
    assert r.status_code == 200
    data = r.json()
    assert "scans" in data and isinstance(data["scans"], list)
