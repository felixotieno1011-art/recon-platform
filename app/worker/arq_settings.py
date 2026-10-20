"""arq WorkerSettings for recon-platform. Started via: python -m arq app.worker.arq_settings.WorkerSettings"""
from __future__ import annotations

import logging

from arq.connections import RedisSettings

from app import config
from app.worker.jobs import run_scan


def _redis_settings() -> RedisSettings:
    # arq's RedisSettings.from_dsn handles redis:// URLs directly.
    return RedisSettings.from_dsn(config.REDIS_URL)


async def startup(ctx):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("arq").setLevel(logging.INFO)
    logging.getLogger("recon").info("worker starting; redis=%s", config.REDIS_URL)


async def shutdown(ctx):
    logging.getLogger("recon").info("worker shutting down")


class WorkerSettings:
    functions = [run_scan]
    redis_settings = _redis_settings()
    max_jobs = 2
    job_timeout = 300
    keep_result = 3600
    on_startup = startup
    on_shutdown = shutdown
