"""RAG + risk scoring + verdict integration tests (ISSUE-047)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from app.agents.risk_agent import RiskAgent
from app.agents.risk_scoring_engine import FACTOR_WEIGHTS, RiskScoringEngine
from app.agents.verdict_resolver import VerdictResolver
from app.core.config import get_settings
from app.core.errors import ConfigurationError
from app.models.agent_io import (
    AttackTechniqueMatch,
    CollectionStatus,
    EvidenceOutput,
    FpSimilarity,
    RAGOutput,
    RiskAgentInput,
    RiskAssessment,
    ScoringMode,
    TriageResult,
)
from app.models.entities import (
    AccountEntity,
    DomainEntity,
    EntitySet,
    HostEntity,
    IPEntity,
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
from app.models.workflow import FP_HIGH_THRESHOLD
from app.services.analysis_only_pipeline import AnalysisOnlyPipeline, assert_analysis_only_mode

pytestmark = pytest.mark.rag


class _FakeWorkingMemory:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], Any] = {}

    async def read(self, event_id: str, key: str) -> Any:
        return self.values.get((event_id, key))

    async def write(self, event_id: str, key: str, value: Any) -> None:
        self.values[(event_id, key)] = value

    async def append_scratchpad(self, event_id: str, note: str) -> None:
        return None


class _FakeEventService:
    def __init__(self) -> None:
        self.risk_updates: list[dict[str, Any]] = []
        self.verdicts: list[FinalVerdict] = []
        self.transitions: list[tuple[str, EventStatus]] = []

    async def update_risk_fields(
        self,
        event_id: str,
        *,
        risk_score: int,
        severity: Severity,
        confidence: float,
        operator: str | None = None,
        factor_names: list[str] | None = None,
    ) -> None:
        self.risk_updates.append(
            {
                "event_id": event_id,
                "risk_score": risk_score,
                "severity": severity,
                "confidence": confidence,
            }
        )

    async def set_final_verdict(
        self,
        event_id: str,
        verdict: FinalVerdict,
        *,
        operator: str | None = None,
        context: Any = None,
    ) -> None:
        self.verdicts.append(verdict)

    async def transition_status(
        self,
        event_id: str,
        target: EventStatus,
        *,
        context: Any = None,
        operator: str | None = None,
        reason: str | None = None,
    ) -> None:
        self.transitions.append((event_id, target))


class _FailingLLM:
    async def chat(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("llm unavailable")


def _evd(
    *,
    source: EvidenceSource,
    evidence_type: str,
    confidence: float,
    event_id: str,
    description: str,
    raw: dict[str, Any],
    mitre: str | None = None,
) -> Evidence:
    return Evidence(
        evidence_id=new_evidence_id(),
        event_id=event_id,
        source=source,
        evidence_type=evidence_type,
        description=description,
        confidence=confidence,
        timestamp=datetime(2024, 6, 15, 9, 0, tzinfo=UTC),
        raw_data=raw,
        mitre_technique=mitre,
        is_conflicting=False,
        related_entities=[],
    )


def _main_triage() -> TriageResult:
    return TriageResult(
        event_type=EventType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        need_investigation=True,
        entities=EntitySet(
            accounts=[AccountEntity(entity_id="a1", username="zhangsan")],
            hosts=[
                HostEntity(
                    entity_id="h1",
                    hostname="PC-FIN-023",
                    ip="10.20.30.23",
                )
            ],
            ips=[
                IPEntity(entity_id="i1", address="10.20.30.23", scope="internal"),
                IPEntity(entity_id="i2", address="203.0.113.88", scope="external"),
            ],
            domains=[DomainEntity(entity_id="d1", fqdn="unknown-upload-example.com")],
        ),
        ioc_list=["203.0.113.88"],
        reasoning="insider exfiltration",
    )


def _main_evidence(event_id: str) -> EvidenceOutput:
    items = [
        _evd(
            source=EvidenceSource.ENDPOINT,
            evidence_type="process_create",
            confidence=0.9,
            event_id=event_id,
            description="powershell archive",
            raw={
                "hostname": "PC-FIN-023",
                "account": "zhangsan",
                "process": "powershell.exe",
                "action": "process_create",
            },
            mitre="T1059.001",
        ),
        _evd(
            source=EvidenceSource.DATA_SECURITY,
            evidence_type="upload",
            confidence=0.88,
            event_id=event_id,
            description="upload finance_report.zip",
            raw={
                "action": "upload",
                "file_name": "finance_report.zip",
                "bytes": 52428800,
            },
            mitre="T1567.002",
        ),
        _evd(
            source=EvidenceSource.NETWORK_FLOW,
            evidence_type="network_flow",
            confidence=0.85,
            event_id=event_id,
            description="external upload traffic",
            raw={
                "src_ip": "10.20.30.23",
                "dst_ip": "203.0.113.88",
                "bytes_out": 52000000,
            },
            mitre="T1041",
        ),
        _evd(
            source=EvidenceSource.THREAT_INTEL,
            evidence_type="ip",
            confidence=0.91,
            event_id=event_id,
            description="ti hit",
            raw={
                "indicator": "203.0.113.88",
                "confidence": 0.91,
                "tags": ["exfil", "unknown_infra"],
            },
        ),
    ]
    return EvidenceOutput(
        evidence_list=items,
        success_sources=["endpoint", "data_security", "network_flow", "threat_intel"],
        failed_sources=[],
        overall_confidence=0.86,
        collection_status=CollectionStatus.COMPLETED,
    )


def _main_rag_output() -> RAGOutput:
    return RAGOutput(
        attack_techniques=[
            AttackTechniqueMatch(
                technique_id="T1567.002",
                technique_name="Exfiltration Over Web Service",
                tactics=["exfiltration"],
                match_confidence=0.92,
                citation_id="cit-rag-1",
            ),
            AttackTechniqueMatch(
                technique_id="T1041",
                technique_name="Exfiltration Over C2 Channel",
                tactics=["exfiltration"],
                match_confidence=0.88,
                citation_id="cit-rag-2",
            ),
            AttackTechniqueMatch(
                technique_id="T1486",
                technique_name="Data Encrypted for Impact",
                tactics=["impact"],
                match_confidence=0.8,
                citation_id="cit-rag-3",
            ),
        ],
    )


def _merged_rule_score(
    engine: RiskScoringEngine,
    *,
    triage: TriageResult,
    evidence: EvidenceOutput,
    rag: RAGOutput | None,
) -> float:
    scores = engine.score(
        triage_result=triage,
        evidence_output=evidence,
        rag_output=rag,
    )
    return sum(scores[name][0] * FACTOR_WEIGHTS[name] for name in FACTOR_WEIGHTS)


class _StubAgent:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.calls: list[Any] = []

    async def execute(self, input: Any) -> Any:
        self.calls.append(input)
        return self.result


class _FailingStubAgent:
    async def execute(self, input: Any) -> Any:
        raise RuntimeError("rag subsystem unavailable")


class _RecordingRiskAgent(RiskAgent):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.rag_inputs: list[RAGOutput | None] = []

    async def _run(self, input: RiskAgentInput) -> RiskAssessment:
        self.rag_inputs.append(input.rag_output)
        return await super()._run(input)


def test_rag_boosts_rule_baseline_for_main_scenario() -> None:
    engine = RiskScoringEngine()
    event_id = f"evt-rag-baseline-{uuid4().hex[:8]}"
    triage = _main_triage()
    evidence = _main_evidence(event_id)
    baseline = _merged_rule_score(engine, triage=triage, evidence=evidence, rag=None)
    with_rag = _merged_rule_score(
        engine,
        triage=triage,
        evidence=evidence,
        rag=_main_rag_output(),
    )
    assert with_rag >= baseline
    assert with_rag >= 70.0


@pytest.mark.asyncio
async def test_main_scenario_with_rag_confirmed_threat() -> None:
    event_id = f"evt-rag-main-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    event_service = _FakeEventService()
    agent = RiskAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=event_service,
    )
    baseline_agent = RiskAgent(
        llm_client=_FailingLLM(),
        working_memory=_FakeWorkingMemory(),
        event_service=_FakeEventService(),
    )
    evidence = _main_evidence(event_id)
    triage = _main_triage()
    baseline = await baseline_agent.execute(
        RiskAgentInput(
            event_id=event_id,
            triage_result=triage,
            evidence_output=evidence,
        )
    )
    output = await agent.execute(
        RiskAgentInput(
            event_id=event_id,
            triage_result=triage,
            evidence_output=evidence,
            rag_output=_main_rag_output(),
        )
    )
    assert output.risk_score >= baseline.risk_score
    assert output.risk_score >= 70
    assert agent.last_verdict is FinalVerdict.CONFIRMED_THREAT
    assert event_service.verdicts[-1] is FinalVerdict.CONFIRMED_THREAT


@pytest.mark.asyncio
async def test_fp_scenario_false_positive_via_rag_similarity() -> None:
    event_id = f"evt-rag-fp-{uuid4().hex[:8]}"
    wm = _FakeWorkingMemory()
    event_service = _FakeEventService()
    agent = RiskAgent(
        llm_client=_FailingLLM(),
        working_memory=wm,
        event_service=event_service,
    )
    weak = EvidenceOutput(
        evidence_list=[
            _evd(
                source=EvidenceSource.DNS,
                evidence_type="dns_query",
                confidence=0.35,
                event_id=event_id,
                description="benign lookup",
                raw={"query": "update.example.com"},
            )
        ],
        success_sources=["dns"],
        failed_sources=[],
        overall_confidence=0.35,
        collection_status=CollectionStatus.DEGRADED,
    )
    rag = RAGOutput(
        fp_similarity=FpSimilarity(max_score=FP_HIGH_THRESHOLD, matched_case_id="fp-case-ops")
    )
    output = await agent.execute(
        RiskAgentInput(
            event_id=event_id,
            triage_result=TriageResult(
                event_type=EventType.OTHER,
                severity=Severity.LOW,
                need_investigation=True,
            ),
            evidence_output=weak,
            rag_output=rag,
        )
    )
    assert output.risk_score < 40
    assert agent.last_verdict is FinalVerdict.FALSE_POSITIVE


def test_close_as_fp_beats_high_rag_fp_similarity() -> None:
    resolver = VerdictResolver()
    rag = RAGOutput(fp_similarity=FpSimilarity(max_score=0.99, matched_case_id="rag-fp"))
    verdict = resolver.resolve(
        RiskAssessment(
            risk_score=85,
            severity=Severity.HIGH,
            confidence=0.8,
            scoring_mode=ScoringMode.RULE_ONLY,
        ),
        false_positive_match={"recommendation": "close_as_fp", "max_score": 0.5},
        rag_output=rag,
    )
    assert verdict is FinalVerdict.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_pipeline_wires_rag_between_evidence_and_risk() -> None:
    event_id = f"evt-rag-pipe-{uuid4().hex[:8]}"
    triage = _main_triage()
    evidence = _main_evidence(event_id)
    rag_output = _main_rag_output()
    risk_agent = _RecordingRiskAgent(
        llm_client=_FailingLLM(),
        working_memory=_FakeWorkingMemory(),
        event_service=_FakeEventService(),
    )
    report = InvestigationReport(
        report_id=report_id_for_event(event_id),
        event_id=event_id,
        title="stub report",
    )
    pipeline = AnalysisOnlyPipeline(
        triage_agent=_StubAgent(triage),
        evidence_agent=_StubAgent(evidence),
        rag_agent=_StubAgent(rag_output),
        risk_agent=risk_agent,
        report_agent=_StubAgent(report),
        event_service=_FakeEventService(),
    )
    result = await pipeline.run(event_id)
    assert result.rag_output == rag_output
    assert result.rag_degraded is False
    assert result.final_verdict is FinalVerdict.CONFIRMED_THREAT
    assert risk_agent.rag_inputs == [rag_output]
    assert result.analysis_only_complete is True


@pytest.mark.asyncio
async def test_pipeline_rag_failure_degrades_without_blocking() -> None:
    event_id = f"evt-rag-fail-{uuid4().hex[:8]}"
    triage = _main_triage()
    evidence = _main_evidence(event_id)
    risk_agent = _RecordingRiskAgent(
        llm_client=_FailingLLM(),
        working_memory=_FakeWorkingMemory(),
        event_service=_FakeEventService(),
    )
    report = InvestigationReport(
        report_id=report_id_for_event(event_id),
        event_id=event_id,
        title="stub report",
    )
    pipeline = AnalysisOnlyPipeline(
        triage_agent=_StubAgent(triage),
        evidence_agent=_StubAgent(evidence),
        rag_agent=_FailingStubAgent(),
        risk_agent=risk_agent,
        report_agent=_StubAgent(report),
        event_service=_FakeEventService(),
    )
    result = await pipeline.run(event_id)
    assert result.rag_output is None
    assert result.rag_degraded is True
    assert result.risk_assessment.risk_score >= 70
    assert result.final_verdict is FinalVerdict.CONFIRMED_THREAT
    assert risk_agent.rag_inputs == [None]
    assert result.report is not None


def test_analysis_only_pipeline_requires_mock_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALLOW_LIVE_SIDE_EFFECTS", "true")
    get_settings.cache_clear()
    try:
        with pytest.raises(ConfigurationError, match="ALLOW_LIVE_SIDE_EFFECTS"):
            assert_analysis_only_mode()
    finally:
        monkeypatch.delenv("ALLOW_LIVE_SIDE_EFFECTS", raising=False)
        get_settings.cache_clear()
