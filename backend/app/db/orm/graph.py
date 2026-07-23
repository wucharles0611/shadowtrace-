"""GraphNodeORM and GraphEdgeORM (ISSUE-050).

PostgreSQL-backed entity-relationship graph derived from evidence.
Neo4j (ISSUE-082) is a P2 enhancement; this module uses only relational tables.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

_TS = DateTime(timezone=True)


class GraphNodeORM(Base):
    __tablename__ = "graph_node"
    __table_args__ = (
        UniqueConstraint("event_id", "entity_type", "entity_value", name="uq_graph_node_identity"),
    )

    node_id: Mapped[str] = mapped_column(String, primary_key=True)
    event_id: Mapped[str] = mapped_column(
        String, ForeignKey("security_event.event_id"), nullable=False, index=True
    )
    entity_type: Mapped[str] = mapped_column(String, nullable=False)
    entity_value: Mapped[str] = mapped_column(String, nullable=False)
    properties: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)


class GraphEdgeORM(Base):
    __tablename__ = "graph_edge"

    edge_id: Mapped[str] = mapped_column(String, primary_key=True)
    event_id: Mapped[str] = mapped_column(
        String, ForeignKey("security_event.event_id"), nullable=False, index=True
    )
    source_node_id: Mapped[str] = mapped_column(String, nullable=False)
    target_node_id: Mapped[str] = mapped_column(String, nullable=False)
    relation_type: Mapped[str] = mapped_column(String, nullable=False)
    evidence_id: Mapped[str] = mapped_column(String, nullable=False)
    occurred_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
