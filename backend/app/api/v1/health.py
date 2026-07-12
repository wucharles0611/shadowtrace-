"""Health check API: GET /api/v1/health."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Response
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from app.core.config import Settings, get_settings

router = APIRouter(tags=["health"])

# Process-wide caches so health probes reuse one pool/connection per URL
# instead of building and tearing one down on every request.
_ENGINES: dict[str, AsyncEngine] = {}
_REDIS_CLIENTS: dict[str, Redis] = {}


def _get_engine(database_url: str) -> AsyncEngine:
    engine = _ENGINES.get(database_url)
    if engine is None:
        engine = create_async_engine(database_url, pool_pre_ping=True)
        _ENGINES[database_url] = engine
    return engine


def _get_redis(redis_url: str) -> Redis:
    client = _REDIS_CLIENTS.get(redis_url)
    if client is None:
        client = Redis.from_url(redis_url, decode_responses=True)
        _REDIS_CLIENTS[redis_url] = client
    return client


async def shutdown_health_clients() -> None:
    """Dispose cached engines / Redis clients on application shutdown."""
    for engine in _ENGINES.values():
        await engine.dispose()
    _ENGINES.clear()
    for client in _REDIS_CLIENTS.values():
        await client.aclose()
    _REDIS_CLIENTS.clear()


async def check_postgres(database_url: str) -> str:
    """Return 'ok' if SELECT 1 succeeds, else 'error'."""
    try:
        engine = _get_engine(database_url)
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return "ok"
    except Exception:  # noqa: BLE001 — health must never raise
        return "error"


async def check_redis(redis_url: str) -> str:
    """Return 'ok' if PING succeeds, else 'error'."""
    try:
        client = _get_redis(redis_url)
        pong = await client.ping()
        return "ok" if pong else "error"
    except Exception:  # noqa: BLE001 — health must never raise
        return "error"


def _component_summary(*, status: str, mode: str, capability: dict[str, str]) -> dict[str, Any]:
    """Adapter/provider summary: status, mode, capability — never credentials."""
    return {
        "status": status,
        "mode": mode,
        "capability": capability,
    }


@router.get("/health")
async def health(
    settings: Annotated[Settings, Depends(get_settings)],
    response: Response,
) -> dict[str, Any]:
    """Report dependency and adapter placeholder health.

    Returns 200 when every hard dependency is reachable, otherwise 503 so that
    HTTP-only probes (compose `curl -f`, load balancers) detect degradation.
    """
    postgres = await check_postgres(settings.database_url)
    redis_status = await check_redis(settings.redis_url)

    # NOTE: capability values below are UNVERIFIED placeholders for the Mock
    # phase. Once real adapters land they must be replaced with actual
    # capability probing (live capabilities default to UNKNOWN).
    source_adapter = _component_summary(
        status="ok" if settings.source_mode == "mock_xdr" else "degraded",
        mode=settings.source_mode,
        capability={
            "LOG_INGESTION": "SUPPORTED" if settings.source_mode == "mock_xdr" else "UNKNOWN",
            "QUERY": "SUPPORTED" if settings.source_mode == "mock_xdr" else "UNKNOWN",
            "EVENT_DISPOSITION": "UNSUPPORTED",
            "ENTITY_RESPONSE": "UNSUPPORTED",
        },
    )
    disposition_adapter = _component_summary(
        status="ok" if settings.disposition_mode == "mock_xdr" else "degraded",
        mode=settings.disposition_mode,
        capability={
            "LOG_INGESTION": "UNSUPPORTED",
            "QUERY": "UNKNOWN",
            "EVENT_DISPOSITION": (
                "SUPPORTED" if settings.disposition_mode == "mock_xdr" else "UNKNOWN"
            ),
            "ENTITY_RESPONSE": (
                "SUPPORTED" if settings.disposition_mode == "mock_xdr" else "UNKNOWN"
            ),
        },
    )
    tool_provider = _component_summary(
        status="ok" if settings.tool_mode == "mock" else "degraded",
        mode=settings.tool_mode,
        capability={
            "query": "SUPPORTED" if settings.tool_mode == "mock" else "UNKNOWN",
            "response": "SUPPORTED" if settings.tool_mode == "mock" else "UNKNOWN",
            "verification": "SUPPORTED" if settings.tool_mode == "mock" else "UNKNOWN",
            "rollback": "SUPPORTED" if settings.tool_mode == "mock" else "UNKNOWN",
        },
    )

    overall = "ok" if postgres == "ok" and redis_status == "ok" else "degraded"
    if overall != "ok":
        response.status_code = 503

    return {
        "status": overall,
        "postgres": postgres,
        "redis": redis_status,
        "source_adapter": source_adapter,
        "disposition_adapter": disposition_adapter,
        "tool_provider": tool_provider,
        "simulation_enabled": settings.simulation_enabled,
        "version": settings.app_version,
    }
