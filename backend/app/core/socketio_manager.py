"""Socket.IO manager — ASGI mount, background Redis subscriber, and sequence (ISSUE-040).

Wraps ``socketio.AsyncServer`` and mounts it on a FastAPI app via
``socketio.ASGIApp``.  A long-lived background task subscribes to
``shadowtrace:events:*`` via Redis ``PSUBSCRIBE`` and broadcasts
every message as a unified envelope into the ``/events`` namespace.

Naming (from spec)
------------------
* Namespace: ``/events``
* Rooms: ``global`` (all connected clients), ``event:{event_id}`` (per-event)
* Envelope: ``type``, ``event_id``, ``sequence``, ``timestamp``, ``payload``
* Sequence key: ``shadowtrace:socketio:seq:{event_id}`` (Redis INCR)
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

import jsonschema
import socketio
from fastapi import FastAPI

from app.core.event_bus import SOCKET_MESSAGE_TYPES, sanitize_payload
from app.core.redis_client import RedisClient
from app.core.socketio_events import (
    GLOBAL_ROOM,
    SOCKETIO_NAMESPACE,
    _event_room,
    register_handlers,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EVENTS_CHANNEL_PATTERN = "shadowtrace:events:*"
_EVENTS_CHANNEL_PREFIX = "shadowtrace:events:"
_SEQUENCE_KEY_PREFIX = "shadowtrace:socketio:seq:"
_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2].parent / "contracts" / "socketio" / "events.schema.json"
)
_RECONNECT_DELAY_S = 2.0
_RECOVERY_DELAY_S = 30.0
_SEQUENCE_TTL_S = 60 * 60 * 24 * 30  # 30 days
_MAX_CONSECUTIVE_FAILURES = 5


def _sequence_key(event_id: str) -> str:
    return f"{_SEQUENCE_KEY_PREFIX}{event_id}"


@lru_cache(maxsize=1)
def _events_schema() -> dict[str, Any]:
    """Load the Socket.IO envelope JSON Schema once per process."""
    return cast(dict[str, Any], json.loads(_SCHEMA_PATH.read_text(encoding="utf-8")))


# ---------------------------------------------------------------------------
# SocketIOManager
# ---------------------------------------------------------------------------


class SocketIOManager:
    """Manage the ``socketio.AsyncServer`` lifecycle and Redis→Socket.IO bridge.

    Parameters
    ----------
    redis:
        The shared ``RedisClient`` used for PSUBSCRIBE and sequence INCR.
    """

    def __init__(self, redis: RedisClient) -> None:
        self._redis = redis
        self._sio = socketio.AsyncServer(
            async_mode="asgi",
            cors_allowed_origins="*",
            logger=False,
        )
        self._listener_task: asyncio.Task[None] | None = None
        self._stopping = False
        self._consecutive_failures = 0
        self._bridge_degraded = False

        register_handlers(self._sio)

    # ------------------------------------------------------------------ #
    # Properties
    # ------------------------------------------------------------------ #

    @property
    def sio(self) -> socketio.AsyncServer:
        """The managed ``AsyncServer`` instance."""
        return self._sio

    @property
    def bridge_active(self) -> bool:
        """True while the Redis→Socket.IO listener task is running."""
        return self._listener_task is not None and not self._listener_task.done()

    @property
    def bridge_degraded(self) -> bool:
        """True when the listener is in a prolonged recovery backoff."""
        return self._bridge_degraded

    # ------------------------------------------------------------------ #
    # FastAPI integration
    # ------------------------------------------------------------------ #

    def mount(self, app: FastAPI) -> socketio.ASGIApp:
        """Wrap *app* so Socket.IO and the FastAPI app share the same ASGI server.

        Returns a new ASGI application.  Callers must use the returned object
        as the uvicorn target.
        """
        wrapped = socketio.ASGIApp(self._sio, other_asgi_app=app, socketio_path="socket.io")
        return wrapped

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        """Start the background Redis→Socket.IO bridge.

        Safe to call multiple times — subsequent calls are no-ops.
        """
        if self._listener_task is not None and not self._listener_task.done():
            return
        self._stopping = False
        self._consecutive_failures = 0
        self._bridge_degraded = False
        self._listener_task = asyncio.create_task(self._listen())
        logger.info("SocketIOManager background listener started")

    async def stop(self) -> None:
        """Stop the background listener gracefully and disconnect all clients."""
        self._stopping = True
        if self._listener_task is not None and not self._listener_task.done():
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
            self._listener_task = None
        try:
            await self._sio.disconnect()
        except Exception:
            logger.warning("SocketIOManager disconnect raised", exc_info=True)
        self._bridge_degraded = False
        logger.info("SocketIOManager stopped")

    # ------------------------------------------------------------------ #
    # Background listener
    # ------------------------------------------------------------------ #

    async def _listen(self) -> None:
        """PSUBSCRIBE ``shadowtrace:events:*`` and bridge to Socket.IO rooms.

        On connection loss, retry with a fixed back-off.  After
        ``_MAX_CONSECUTIVE_FAILURES`` consecutive failures the listener
        enters a longer recovery delay, then retries (frontend may poll REST).
        """
        while not self._stopping:
            try:
                await self._run_subscriber()
                self._consecutive_failures = 0
                self._bridge_degraded = False
            except asyncio.CancelledError:
                break
            except Exception:
                self._consecutive_failures += 1
                if self._consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                    self._bridge_degraded = True
                    logger.critical(
                        "SocketIOManager subscriber failed %d consecutive times — "
                        "entering %.0fs recovery backoff before retry",
                        self._consecutive_failures,
                        _RECOVERY_DELAY_S,
                        exc_info=True,
                    )
                    self._consecutive_failures = 0
                    await asyncio.sleep(_RECOVERY_DELAY_S)
                    self._bridge_degraded = False
                    continue
                logger.warning(
                    "SocketIOManager subscriber error — retrying in %.1fs (attempt %d/%d)",
                    _RECONNECT_DELAY_S,
                    self._consecutive_failures,
                    _MAX_CONSECUTIVE_FAILURES,
                    exc_info=True,
                )
                await asyncio.sleep(_RECONNECT_DELAY_S)

    async def _run_subscriber(self) -> None:
        """Single PSUBSCRIBE session: decode envelopes and broadcast."""
        pubsub = None
        try:
            client = self._redis.get_client()
            pubsub = client.pubsub()
            await pubsub.psubscribe(_EVENTS_CHANNEL_PATTERN)

            async for message in pubsub.listen():
                if self._stopping:
                    break
                if message is None:
                    continue
                if message.get("type") != "pmessage":
                    continue

                channel_raw = message.get("channel")
                data_raw = message.get("data")
                if not isinstance(channel_raw, (str, bytes)) or data_raw is None:
                    continue

                channel_bytes = (
                    channel_raw.encode("utf-8") if isinstance(channel_raw, str) else channel_raw
                )
                if not isinstance(data_raw, (bytes, str, memoryview)):
                    logger.warning(
                        "SocketIOManager unexpected data_raw type=%s — dropped",
                        type(data_raw).__name__,
                    )
                    continue

                await self._dispatch(channel_bytes, data_raw)

        except asyncio.CancelledError:
            raise
        except Exception:
            if not self._stopping:
                raise
        finally:
            if pubsub is not None:
                try:
                    await pubsub.punsubscribe()
                except Exception:
                    pass
                try:
                    await pubsub.aclose()  # type: ignore[no-untyped-call]
                except Exception:
                    pass

    async def _increment_sequence(self, event_id: str) -> int | None:
        """Return the next per-event sequence or None when Redis INCR fails."""
        seq_key = _sequence_key(event_id)
        try:
            redis_client = self._redis.get_client()
            seq = int(await redis_client.incr(seq_key))
            await redis_client.expire(seq_key, _SEQUENCE_TTL_S)
            return seq
        except Exception:
            logger.warning(
                "SocketIOManager sequence INCR failed for event_id=%s — skipping emit",
                event_id,
                exc_info=True,
            )
            return None

    async def _dispatch(self, channel_raw: bytes, data_raw: bytes | str | memoryview) -> None:
        """Decode one Redis message and emit to the appropriate rooms."""
        if self._stopping:
            return

        try:
            channel = channel_raw.decode("utf-8")
        except UnicodeDecodeError:
            logger.warning("SocketIOManager channel name contains invalid UTF-8 — dropped")
            return

        if not channel.startswith(_EVENTS_CHANNEL_PREFIX):
            return
        event_id = channel[len(_EVENTS_CHANNEL_PREFIX) :]
        if not event_id:
            return

        try:
            envelope = RedisClient.loads(data_raw)
        except Exception:
            logger.warning(
                "SocketIOManager received undecodable payload on %s",
                channel,
                exc_info=True,
            )
            return

        if not isinstance(envelope, dict):
            return

        message_type = envelope.get("message_type")
        if not message_type or not isinstance(message_type, str):
            logger.warning(
                "SocketIOManager envelope missing message_type on %s — dropped",
                channel,
            )
            return

        if message_type not in SOCKET_MESSAGE_TYPES:
            logger.warning(
                "SocketIOManager unknown message_type=%s on %s — dropped",
                message_type,
                channel,
            )
            return

        seq = await self._increment_sequence(event_id)
        if seq is None:
            return

        raw_payload = envelope.get("payload", {})
        safe_payload = sanitize_payload(raw_payload if isinstance(raw_payload, dict) else {})
        if not isinstance(safe_payload, dict):
            safe_payload = {}

        bus_timestamp = envelope.get("timestamp")
        if isinstance(bus_timestamp, str):
            timestamp = bus_timestamp
        else:
            timestamp = datetime.now(UTC).isoformat()

        socket_envelope: dict[str, Any] = {
            "type": message_type,
            "event_id": event_id,
            "sequence": seq,
            "timestamp": timestamp,
            "payload": safe_payload,
        }

        try:
            jsonschema.validate(instance=socket_envelope, schema=_events_schema())
        except jsonschema.ValidationError:
            logger.warning(
                "SocketIOManager envelope failed schema validation event_id=%s type=%s — dropped",
                event_id,
                message_type,
            )
            return

        # Subscribed detail clients leave ``global`` on subscribe, so they
        # receive once via ``event:{event_id}``; dashboard clients stay in
        # ``global`` only and receive once via the global emit.
        event_room = _event_room(event_id)
        results = await asyncio.gather(
            self._sio.emit(
                "event",
                socket_envelope,
                room=event_room,
                namespace=SOCKETIO_NAMESPACE,
            ),
            self._sio.emit(
                "event",
                socket_envelope,
                room=GLOBAL_ROOM,
                namespace=SOCKETIO_NAMESPACE,
            ),
            return_exceptions=True,
        )
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                target = "event_room" if i == 0 else "global"
                logger.warning(
                    "SocketIOManager emit failed event_id=%s target=%s type=%s",
                    event_id,
                    target,
                    message_type,
                    exc_info=result,
                )


__all__ = ["SocketIOManager", "_events_schema", "_sequence_key"]
