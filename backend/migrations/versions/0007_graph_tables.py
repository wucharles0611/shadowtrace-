"""graph_node and graph_edge tables for ISSUE-050 GraphAgent

Revision ID: 0007_graph_tables
Revises: 0006_knowledge_chunk
Create Date: 2026-07-23 00:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_graph_tables"
down_revision: str | None = "0006_knowledge_chunk"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "graph_node",
        sa.Column("node_id", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("entity_type", sa.String(), nullable=False),
        sa.Column("entity_value", sa.String(), nullable=False),
        sa.Column(
            "properties",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("node_id", name=op.f("pk_graph_node")),
        sa.UniqueConstraint(
            "event_id",
            "entity_type",
            "entity_value",
            name=op.f("uq_graph_node_identity"),
        ),
    )
    op.create_index(op.f("ix_graph_node_event_id"), "graph_node", ["event_id"], unique=False)

    op.create_table(
        "graph_edge",
        sa.Column("edge_id", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("source_node_id", sa.String(), nullable=False),
        sa.Column("target_node_id", sa.String(), nullable=False),
        sa.Column("relation_type", sa.String(), nullable=False),
        sa.Column("evidence_id", sa.String(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("edge_id", name=op.f("pk_graph_edge")),
    )
    op.create_index(op.f("ix_graph_edge_event_id"), "graph_edge", ["event_id"], unique=False)


def downgrade() -> None:
    op.drop_table("graph_edge")
    op.drop_table("graph_node")
