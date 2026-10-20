"""Starlette app entrypoint. Started via: uvicorn app.main:app"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

from app import config, db
from app.api.routes import routes as api_routes
from app.api.ws import routes as ws_routes
from app.scope_guard import load_scope

log = logging.getLogger("recon.main")


@asynccontextmanager
async def lifespan(app):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    db.init_db()
    load_scope()
    log.info("recon-platform API ready — db=%s", config.DB_PATH)
    yield
    log.info("recon-platform API shutting down")


middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=True,
    ),
]

app = Starlette(routes=api_routes + ws_routes, middleware=middleware, lifespan=lifespan)
