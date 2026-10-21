"""Bearer-token auth for state-changing API endpoints."""
from __future__ import annotations

import functools
import logging
import secrets

from starlette.requests import Request
from starlette.responses import JSONResponse

from app import config

log = logging.getLogger("recon.api.auth")


def _extract_token(request: Request) -> str | None:
    header = request.headers.get("authorization") or ""
    if not header.lower().startswith("bearer "):
        return None
    return header[7:].strip() or None


def require_auth(fn):
    """Decorator: reject requests missing a valid Bearer token."""
    @functools.wraps(fn)
    async def wrapper(request: Request):
        provided = _extract_token(request)
        if not provided:
            return JSONResponse(
                {"error": "missing bearer token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        # timing-safe compare; both sides are str, secrets.compare_digest accepts that
        if not secrets.compare_digest(provided, config.API_TOKEN):
            log.warning("rejected request with bad token from %s", request.client)
            return JSONResponse(
                {"error": "invalid token"},
                status_code=403,
                headers={"WWW-Authenticate": "Bearer"},
            )
        return await fn(request)
    return wrapper
