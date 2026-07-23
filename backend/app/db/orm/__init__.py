"""ORM models for per-issue tables (ISSUE-041, ISSUE-050)."""

from app.db.orm.graph import GraphEdgeORM, GraphNodeORM
from app.db.orm.knowledge import KnowledgeChunkORM

__all__ = ["GraphEdgeORM", "GraphNodeORM", "KnowledgeChunkORM"]
