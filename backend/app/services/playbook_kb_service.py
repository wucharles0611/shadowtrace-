"""PlaybookKBService: SOAR playbook knowledge base operations (ISSUE-044)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.enums import ActionLevel, EventType
from app.models.knowledge import KnowledgeChunk
from app.models.playbook import Playbook, PlaybookStep
from app.models.tool_meta import ToolMeta
from app.services.knowledge_store import KnowledgeStore
from app.tools.specs import baseline_tool_index

KB_NAME = "playbook_kb"
_SEVERITY_ORDINAL: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_OTHER_ALLOWED_LEVELS = frozenset({ActionLevel.L0, ActionLevel.L1})


def _derive_chunk_id(playbook_id: str) -> str:
    digest = hashlib.sha256(f"playbook:{playbook_id}".encode()).hexdigest()[:16]
    return f"pbk-{digest}"


def _severity_ordinal(severity: str) -> int:
    return _SEVERITY_ORDINAL.get(severity, 99)


def _meta_matches_filters(meta: dict[str, Any], event_type: str, query_ordinal: int) -> bool:
    if meta.get("event_type") != event_type:
        return False
    return _severity_ordinal(str(meta.get("min_severity", ""))) <= query_ordinal


def _playbook_from_metadata(meta: dict[str, Any]) -> Playbook:
    steps_raw = meta.get("steps", [])
    steps = [PlaybookStep.model_validate(s) for s in steps_raw]
    return Playbook(
        playbook_id=meta["playbook_id"],
        playbook_name=meta["playbook_name"],
        event_type=meta["event_type"],
        min_severity=meta["min_severity"],
        description=meta.get("description", ""),
        steps=steps,
    )


def _validate_steps(steps: list[PlaybookStep], playbook_id: str, event_type: EventType) -> None:
    """Static validation: tool_name/action_level vs ToolMeta; other playbooks are l0/l1 only."""
    index = baseline_tool_index()
    for step in steps:
        meta: ToolMeta | None = index.get(step.tool_name)
        if meta is None:
            raise ValueError(
                f"Playbook {playbook_id} step {step.step_order}: "
                f"unknown tool_name '{step.tool_name}'"
            )
        if step.action_level != meta.action_level:
            raise ValueError(
                f"Playbook {playbook_id} step {step.step_order} "
                f"({step.tool_name}): action_level {step.action_level.value} "
                f"does not match ToolMeta.action_level {meta.action_level.value}"
            )
        if event_type == EventType.OTHER and step.action_level not in _OTHER_ALLOWED_LEVELS:
            raise ValueError(
                f"Playbook {playbook_id} step {step.step_order}: "
                f"event_type 'other' only allows l0/l1 actions, "
                f"got {step.action_level.value}"
            )


def _format_content(pb: Playbook) -> str:
    step_names = "; ".join(s.action_name for s in pb.steps)
    return (
        f"Playbook: {pb.playbook_name}\n"
        f"Event Type: {pb.event_type.value}\n"
        f"Min Severity: {pb.min_severity.value}\n"
        f"Description: {pb.description}\n"
        f"Steps: {step_names}"
    )


class PlaybookKBService:
    """Manage the SOAR playbook knowledge base.

    Provides file-based loading with static validation (tool_name + action_level
    against ToolMeta), idempotent upsert, lookup by playbook_id, and filtered
    search by event_type + severity with optional semantic ranking.
    """

    def __init__(
        self,
        store: KnowledgeStore,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._store = store
        self._session_factory = session_factory

    async def load_from_file(self, path: str | Path) -> int:
        """Load playbooks from a JSON file, validate, and upsert into playbook_kb.

        Returns the number of playbooks loaded. Repeated loads are idempotent.
        Raises ValueError if any step references an unknown tool_name or has an
        action_level that disagrees with the ToolMeta declaration.
        """
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        raw_playbooks: list[dict[str, Any]] = data["playbooks"]

        playbooks: list[Playbook] = []
        for raw in raw_playbooks:
            pb = Playbook.model_validate(raw)
            _validate_steps(pb.steps, pb.playbook_id, pb.event_type)
            playbooks.append(pb)

        chunks: list[KnowledgeChunk] = []
        for pb in playbooks:
            chunk_id = _derive_chunk_id(pb.playbook_id)
            content = _format_content(pb)
            metadata: dict[str, Any] = {
                "playbook_id": pb.playbook_id,
                "playbook_name": pb.playbook_name,
                "event_type": pb.event_type.value,
                "min_severity": pb.min_severity.value,
                "description": pb.description,
                "steps": [s.model_dump(mode="json") for s in pb.steps],
            }
            chunks.append(
                KnowledgeChunk(
                    chunk_id=chunk_id,
                    kb_name=KB_NAME,
                    content=content,
                    metadata=metadata,
                )
            )

        await self._store.upsert_chunks(KB_NAME, chunks)
        return len(chunks)

    async def _search_by_severity_order(
        self,
        event_type: str,
        query_ordinal: int,
        top_k: int,
    ) -> list[Playbook]:
        """Return playbooks filtered by event_type/min_severity, severity-descending."""
        sql = text(
            """
            SELECT metadata
            FROM knowledge_chunk
            WHERE kb_name = :kb_name
              AND metadata ->> 'event_type' = :event_type
              AND (
                CASE metadata ->> 'min_severity'
                  WHEN 'low' THEN 0
                  WHEN 'medium' THEN 1
                  WHEN 'high' THEN 2
                  WHEN 'critical' THEN 3
                  ELSE 99
                END
              ) <= :query_ordinal
            ORDER BY (
              CASE metadata ->> 'min_severity'
                WHEN 'low' THEN 0
                WHEN 'medium' THEN 1
                WHEN 'high' THEN 2
                WHEN 'critical' THEN 3
                ELSE 99
              END
            ) DESC
            LIMIT :top_k
            """
        )
        async with self._session_factory() as session:
            result = await session.execute(
                sql,
                {
                    "kb_name": KB_NAME,
                    "event_type": event_type,
                    "query_ordinal": query_ordinal,
                    "top_k": top_k,
                },
            )
            rows = result.fetchall()
        return [_playbook_from_metadata(row.metadata or {}) for row in rows]

    async def search_playbooks(
        self,
        event_type: str,
        severity: str,
        query_text: str | None = None,
        top_k: int = 3,
    ) -> list[Playbook]:
        """Search playbooks by event_type and min_severity, with optional semantic ranking.

        Only returns playbooks whose ``event_type`` matches exactly and whose
        ``min_severity`` ordinal is <= the query severity ordinal.  When
        *query_text* is provided, results are ranked by vector/keyword hybrid
        similarity; otherwise they are returned in severity-descending order.
        """
        query_ordinal = _SEVERITY_ORDINAL.get(severity)
        if query_ordinal is None:
            raise ValueError(
                f"Unknown severity '{severity}'; must be one of {sorted(_SEVERITY_ORDINAL.keys())}"
            )

        if query_text is None:
            return await self._search_by_severity_order(event_type, query_ordinal, top_k)

        chunk_count = await self._store.count(KB_NAME)
        fetch_k = max(top_k * 5, chunk_count, top_k)
        hits = await self._store.hybrid_search(KB_NAME, query_text, top_k=fetch_k)
        filtered = [
            hit for hit in hits if _meta_matches_filters(hit.metadata, event_type, query_ordinal)
        ]
        return [_playbook_from_metadata(hit.metadata) for hit in filtered[:top_k]]

    async def get_playbook(self, playbook_id: str) -> Playbook | None:
        """Look up a single playbook by its playbook_id."""
        sql = text(
            """
            SELECT metadata
            FROM knowledge_chunk
            WHERE kb_name = :kb_name
              AND metadata ->> 'playbook_id' = :playbook_id
            """
        )
        async with self._session_factory() as session:
            result = await session.execute(
                sql,
                {"kb_name": KB_NAME, "playbook_id": playbook_id},
            )
            row = result.fetchone()
            if row is None:
                return None
            return _playbook_from_metadata(row.metadata or {})
