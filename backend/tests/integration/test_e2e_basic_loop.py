"""Minimal analysis-only loop coverage for ISSUE-039 / ISSUE-047 gate.

Full four-scenario ISSUE-039 coverage lands with ISSUE-038 API wiring; this module
asserts the basic loop survives RAG degradation (ISSUE-047 acceptance #2).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from app.agents.risk_agent import RiskAgent
from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    TriageResult,
)
from app.models.enums import (
    EventStatus,
    EventType,
    EvidenceSource,
    FinalVerdict,
    Severity,
)
from app.models.evidence import Evidence
from app.models.ids import new_evidence_id, report_id_for_event
from app.models.report import InvestigationReport
from app.services.analysis_only_pipeline import AnalysisOnlyPipeline

pytestmark = pytest.mark.e2e_basic


class _FakeEventService:
    def __init__(self) -> None:
        self.transitions: list[EventStatus] = []

    async def transition_status(
        self,
        event_id: str,
        target: EventStatus,
        *,
        context: Any = None,
        operator: str | None = None,
        reason: str | None = None,
    ) -> None:
        self.transitions.append(target)

    async def update_risk_fields(self, *args: Any, **kwargs: Any) -> None:
        return None

    async def set_final_verdict(self, *args: Any, **kwargs: Any) -> None:
        return None


class _FakeWorkingMemory:
    async def read(self, event_id: str, key: str) -> Any:
        return None

    async def write(self, event_id: str, key: str, value: Any) -> None:
        return None

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        return None


class _StubAgent:
    def __init__(self, result: Any) -> None:
        self.result = result

    async def execute(self, input: Any) -> Any:
        return self.result


class _FailingRAGAgent:
    async def execute(self, input: Any) -> Any:
        raise RuntimeError("rag unavailable")


class _FailingLLM:
    async def chat(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("llm unavailable")


def _evidence(event_id: str) -> EvidenceOutput:
    items = [
        Evidence(
            evidence_id=new_evidence_id(),
            event_id=event_id,
            source=EvidenceSource.ENDPOINT,
            evidence_type="process_create",
            description="powershell archive",
            confidence=0.9,
            timestamp=datetime(2024, 6, 15, 9, 0, tzinfo=UTC),
            raw_data={
                "hostname": "PC-FIN-023",
                "account": "zhangsan",
                "process": "powershell.exe",
                "action": "process_create",
            },
            mitre_technique="T1059.001",
            is_conflicting=False,
            related_entities=[],
        ),
        Evidence(
            evidence_id=new_evidence_id(),
            event_id=event_id,
            source=EvidenceSource.DATA_SECURITY,
            evidence_type="upload",
            description="upload finance_report.zip",
            confidence=0.88,
            timestamp=datetime(2024, 6, 15, 9, 0, tzinfo=UTC),
            raw_data={
                "action": "upload",
                "file_name": "finance_report.zip",
                "bytes": 52428800,
            },
            mitre_technique="T1567.002",
            is_conflicting=False,
            related_entities=[],
        ),
        Evidence(
            evidence_id=new_evidence_id(),
            event_id=event_id,
            source=EvidenceSource.NETWORK_FLOW,
            evidence_type="network_flow",
            description="upload to 203.0.113.88",
            confidence=0.9,
            timestamp=datetime(2024, 6, 15, 9, 0, tzinfo=UTC),
            raw_data={
                "dst_ip": "203.0.113.88",
                "bytes_out": 52000000,
                "action": "upload",
            },
            mitre_technique="T1041",
            is_conflicting=False,
            related_entities=[],
        ),
        Evidence(
            evidence_id=new_evidence_id(),
            event_id=event_id,
            source=EvidenceSource.THREAT_INTEL,
            evidence_type="ip",
            description="ti hit",
            confidence=0.9,
            timestamp=datetime(2024, 6, 15, 9, 0, tzinfo=UTC),
            raw_data={
                "indicator": "203.0.113.88",
                "confidence": 0.9,
                "tags": ["exfil", "unknown_infra"],
            },
            is_conflicting=False,
            related_entities=[],
        ),
    ]
    return EvidenceOutput(
        evidence_list=items,
        success_sources=["endpoint", "data_security", "network_flow", "threat_intel"],
        failed_sources=[],
        overall_confidence=0.88,
        collection_status=CollectionStatus.COMPLETED,
    )


@pytest.mark.asyncio
async def test_basic_loop_survives_rag_failure() -> None:
    """ISSUE-047: RAG failure must not break analysis-only scoring + report."""
    event_id = f"evt-e2e-rag-fail-{uuid4().hex[:8]}"
    triage = TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        reasoning="basic loop",
    )
    evidence = _evidence(event_id)
    event_service = _FakeEventService()
    risk_agent = RiskAgent(
        llm_client=_FailingLLM(),
        working_memory=_FakeWorkingMemory(),
        event_service=event_service,
    )
    report = InvestigationReport(
        report_id=report_id_for_event(event_id),
        event_id=event_id,
        title="basic loop report",
    )
    pipeline = AnalysisOnlyPipeline(
        triage_agent=_StubAgent(triage),
        evidence_agent=_StubAgent(evidence),
        rag_agent=_FailingRAGAgent(),
        risk_agent=risk_agent,
        report_agent=_StubAgent(report),
        event_service=event_service,
    )
    result = await pipeline.run(event_id)

    assert result.rag_degraded is True
    assert result.risk_assessment.risk_score >= 70
    assert result.final_verdict is FinalVerdict.CONFIRMED_THREAT
    assert result.report is not None
    assert EventStatus.TRIAGING in event_service.transitions
    assert EventStatus.REPORTING in event_service.transitions
    assert EventStatus.CLOSED not in event_service.transitions
