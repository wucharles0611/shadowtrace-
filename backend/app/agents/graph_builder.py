"""GraphBuilder: evidence-to-graph extraction rules (ISSUE-050).

Each EvidenceSource has one extraction rule that produces nodes and directed edges.
The builder infers entity types from ``related_entities`` string values via
heuristics (IP-like, domain-like, hostname-like, process-like, file-like,
account-like), combined with the evidence source for disambiguation.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from app.models.agent_io import GraphEdge, GraphNode, GraphRelationType
from app.models.enums import EvidenceSource
from app.models.evidence import Evidence


def _node_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8]


def _make_node_id(event_id: str, entity_type: str, entity_value: str) -> str:
    """Derive a stable node_id: ``node-{8hex}`` from event+type+value."""
    digest = _node_hash(f"{event_id}|{entity_type}|{entity_value.lower()}")
    return f"node-{digest}"


def _make_edge_id(
    event_id: str,
    source_node_id: str,
    target_node_id: str,
    relation_type: GraphRelationType,
    evidence_id: str,
) -> str:
    """Derive a stable edge_id: ``edge-{8hex}``."""
    seed = f"{event_id}|{source_node_id}|{target_node_id}|{relation_type.value}|{evidence_id}"
    digest = _node_hash(seed)
    return f"edge-{digest}"


# --------------------------------------------------------------------------- #
# Entity-type inference heuristics
# --------------------------------------------------------------------------- #

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Known TLDs so we don't confuse file extensions (.exe, .zip, .com, …)
# with domain suffixes.  Domain detection is gated on membership here.
_KNOWN_TLDS: frozenset[str] = frozenset(
    {
        "com",
        "org",
        "net",
        "edu",
        "gov",
        "mil",
        "int",
        "io",
        "co",
        "uk",
        "de",
        "cn",
        "ru",
        "jp",
        "fr",
        "br",
        "au",
        "in",
        "it",
        "nl",
        "se",
        "ch",
        "es",
        "info",
        "biz",
        "tv",
        "me",
        "app",
        "dev",
        "cloud",
        "online",
        "site",
        "store",
        "xyz",
        "tech",
        "news",
        "local",
        "internal",
        "corp",
        "lan",
        "test",
        "example",
    }
)

_PROCESS_EXT = frozenset(
    {
        ".exe",
        ".dll",
        ".sys",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".py",
        ".sh",
        ".bin",
        ".com",
        ".scr",
        ".msi",
    }
)
_FILE_EXT = frozenset(
    {
        ".zip",
        ".rar",
        ".7z",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".txt",
        ".csv",
        ".json",
        ".xml",
        ".sql",
        ".db",
        ".sqlite",
        ".jpg",
        ".png",
        ".gif",
        ".bmp",
        ".svg",
        ".log",
        ".cfg",
        ".ini",
        ".conf",
        ".pst",
        ".ost",
    }
)


def _looks_ip(value: str) -> bool:
    return bool(_IP_RE.match(value))


def _looks_domain(value: str) -> bool:
    """Domain = not IP, contains dot, TLD in known list."""
    if _looks_ip(value):
        return False
    if "." not in value:
        return False
    tld = value.rsplit(".", 1)[-1].lower()
    return tld in _KNOWN_TLDS


def _looks_hostname(value: str) -> bool:
    """Windows hostnames like PC-FIN-023, DC-01, SRV-WEB."""
    if _looks_ip(value) or _looks_domain(value):
        return False
    # Contains hyphen + uppercase → likely Windows hostname
    if "-" in value and any(c.isupper() for c in value):
        return True
    # Pattern: LETTERS-DIGITS or DIGITS-NAME
    if re.match(r"^[A-Z]{2,6}-\d{2,5}$", value):
        return True
    if re.match(r"^[A-Z]+-[A-Z]+-\d+$", value):
        return True
    if re.match(r"^[A-Z]+-\d+$", value):
        return True
    return False


def _looks_process(value: str) -> bool:
    lower = value.lower()
    for ext in _PROCESS_EXT:
        if lower.endswith(ext):
            return True
    return False


def _looks_file(value: str) -> bool:
    lower = value.lower()
    for ext in _FILE_EXT:
        if lower.endswith(ext):
            return True
    # Path-like patterns
    if "/" in value or "\\" in value:
        return True
    return False


def _infer_entity_types(
    values: list[str],
    source: EvidenceSource,
) -> list[tuple[str, str]]:
    """Infer (entity_type, entity_value) pairs — domain checked before process/file
    so ``cloud-storage.example.com`` is never misclassified as a ``.com`` process."""
    pairs: list[tuple[str, str]] = []

    for val in values:
        v = str(val).strip()
        if not v:
            continue
        if _looks_ip(v):
            pairs.append(("ip", v))
        elif _looks_domain(v):
            pairs.append(("domain", v))
        elif _looks_hostname(v):
            pairs.append(("host", v))
        elif _looks_process(v):
            pairs.append(("process", v))
        elif _looks_file(v):
            pairs.append(("file", v))
        else:
            pairs.append(("account", v))

    return pairs


# --------------------------------------------------------------------------- #
# Per-source extraction rules
# --------------------------------------------------------------------------- #


def _extract_identity(
    event_id: str,
    evidence: Evidence,
    entities: list[tuple[str, str]],
) -> tuple[list[GraphNode], list[GraphEdge]]:
    """identity evidence → logged_in_from (account→ip), logged_in_to (account→host)."""
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    accounts = [e for e in entities if e[0] == "account"]
    ips = [e for e in entities if e[0] == "ip"]
    hosts = [e for e in entities if e[0] == "host"]

    for account in accounts:
        for ip in ips:
            src_id = _make_node_id(event_id, account[0], account[1])
            tgt_id = _make_node_id(event_id, ip[0], ip[1])
            nodes.extend(
                [
                    _make_node(event_id, account[0], account[1], src_id),
                    _make_node(event_id, ip[0], ip[1], tgt_id),
                ]
            )
            edges.append(
                GraphEdge(
                    edge_id=_make_edge_id(
                        event_id,
                        src_id,
                        tgt_id,
                        GraphRelationType.LOGGED_IN_FROM,
                        evidence.evidence_id,
                    ),
                    event_id=event_id,
                    source_node_id=src_id,
                    target_node_id=tgt_id,
                    relation_type=GraphRelationType.LOGGED_IN_FROM,
                    evidence_id=evidence.evidence_id,
                    occurred_at=evidence.timestamp,
                )
            )
        for host in hosts:
            src_id = _make_node_id(event_id, account[0], account[1])
            tgt_id = _make_node_id(event_id, host[0], host[1])
            nodes.extend(
                [
                    _make_node(event_id, account[0], account[1], src_id),
                    _make_node(event_id, host[0], host[1], tgt_id),
                ]
            )
            edges.append(
                GraphEdge(
                    edge_id=_make_edge_id(
                        event_id,
                        src_id,
                        tgt_id,
                        GraphRelationType.LOGGED_IN_TO,
                        evidence.evidence_id,
                    ),
                    event_id=event_id,
                    source_node_id=src_id,
                    target_node_id=tgt_id,
                    relation_type=GraphRelationType.LOGGED_IN_TO,
                    evidence_id=evidence.evidence_id,
                    occurred_at=evidence.timestamp,
                )
            )
    nodes.extend(_ensure_entity_nodes(event_id, entities, nodes))
    return nodes, edges


def _extract_endpoint(
    event_id: str,
    evidence: Evidence,
    entities: list[tuple[str, str]],
) -> tuple[list[GraphNode], list[GraphEdge]]:
    """endpoint evidence → executed (host→process)."""
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    hosts = [e for e in entities if e[0] == "host"]
    processes = [e for e in entities if e[0] == "process"]

    for host in hosts:
        for proc in processes:
            src_id = _make_node_id(event_id, host[0], host[1])
            tgt_id = _make_node_id(event_id, proc[0], proc[1])
            nodes.extend(
                [
                    _make_node(event_id, host[0], host[1], src_id),
                    _make_node(event_id, proc[0], proc[1], tgt_id),
                ]
            )
            edges.append(
                GraphEdge(
                    edge_id=_make_edge_id(
                        event_id, src_id, tgt_id, GraphRelationType.EXECUTED, evidence.evidence_id
                    ),
                    event_id=event_id,
                    source_node_id=src_id,
                    target_node_id=tgt_id,
                    relation_type=GraphRelationType.EXECUTED,
                    evidence_id=evidence.evidence_id,
                    occurred_at=evidence.timestamp,
                )
            )
    nodes.extend(_ensure_entity_nodes(event_id, entities, nodes))
    return nodes, edges


def _extract_data_security(
    event_id: str,
    evidence: Evidence,
    entities: list[tuple[str, str]],
) -> tuple[list[GraphNode], list[GraphEdge]]:
    """data_security evidence → accessed (process/account→file), uploaded_to (file→ip/domain)."""
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    files = [e for e in entities if e[0] == "file"]
    actors = [e for e in entities if e[0] in ("process", "account")]
    ips = [e for e in entities if e[0] == "ip"]
    domains = [e for e in entities if e[0] == "domain"]

    # accessed: process/account → file
    for actor in actors:
        for f in files:
            src_id = _make_node_id(event_id, actor[0], actor[1])
            tgt_id = _make_node_id(event_id, f[0], f[1])
            nodes.extend(
                [
                    _make_node(event_id, actor[0], actor[1], src_id),
                    _make_node(event_id, f[0], f[1], tgt_id),
                ]
            )
            edges.append(
                GraphEdge(
                    edge_id=_make_edge_id(
                        event_id, src_id, tgt_id, GraphRelationType.ACCESSED, evidence.evidence_id
                    ),
                    event_id=event_id,
                    source_node_id=src_id,
                    target_node_id=tgt_id,
                    relation_type=GraphRelationType.ACCESSED,
                    evidence_id=evidence.evidence_id,
                    occurred_at=evidence.timestamp,
                )
            )

    # uploaded_to: file → ip/domain
    for f in files:
        for ip in ips:
            src_id = _make_node_id(event_id, f[0], f[1])
            tgt_id = _make_node_id(event_id, ip[0], ip[1])
            nodes.extend(
                [
                    _make_node(event_id, f[0], f[1], src_id),
                    _make_node(event_id, ip[0], ip[1], tgt_id),
                ]
            )
            edges.append(
                GraphEdge(
                    edge_id=_make_edge_id(
                        event_id,
                        src_id,
                        tgt_id,
                        GraphRelationType.UPLOADED_TO,
                        evidence.evidence_id,
                    ),
                    event_id=event_id,
                    source_node_id=src_id,
                    target_node_id=tgt_id,
                    relation_type=GraphRelationType.UPLOADED_TO,
                    evidence_id=evidence.evidence_id,
                    occurred_at=evidence.timestamp,
                )
            )
        for dom in domains:
            src_id = _make_node_id(event_id, f[0], f[1])
            tgt_id = _make_node_id(event_id, dom[0], dom[1])
            nodes.extend(
                [
                    _make_node(event_id, f[0], f[1], src_id),
                    _make_node(event_id, dom[0], dom[1], tgt_id),
                ]
            )
            edges.append(
                GraphEdge(
                    edge_id=_make_edge_id(
                        event_id,
                        src_id,
                        tgt_id,
                        GraphRelationType.UPLOADED_TO,
                        evidence.evidence_id,
                    ),
                    event_id=event_id,
                    source_node_id=src_id,
                    target_node_id=tgt_id,
                    relation_type=GraphRelationType.UPLOADED_TO,
                    evidence_id=evidence.evidence_id,
                    occurred_at=evidence.timestamp,
                )
            )

    nodes.extend(_ensure_entity_nodes(event_id, entities, nodes))
    return nodes, edges


def _extract_network_flow(
    event_id: str,
    evidence: Evidence,
    entities: list[tuple[str, str]],
) -> tuple[list[GraphNode], list[GraphEdge]]:
    """network_flow evidence → connected_to (host→ip)."""
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    hosts = [e for e in entities if e[0] == "host"]
    ips = [e for e in entities if e[0] == "ip"]

    for host in hosts:
        for ip in ips:
            src_id = _make_node_id(event_id, host[0], host[1])
            tgt_id = _make_node_id(event_id, ip[0], ip[1])
            nodes.extend(
                [
                    _make_node(event_id, host[0], host[1], src_id),
                    _make_node(event_id, ip[0], ip[1], tgt_id),
                ]
            )
            edges.append(
                GraphEdge(
                    edge_id=_make_edge_id(
                        event_id,
                        src_id,
                        tgt_id,
                        GraphRelationType.CONNECTED_TO,
                        evidence.evidence_id,
                    ),
                    event_id=event_id,
                    source_node_id=src_id,
                    target_node_id=tgt_id,
                    relation_type=GraphRelationType.CONNECTED_TO,
                    evidence_id=evidence.evidence_id,
                    occurred_at=evidence.timestamp,
                )
            )
    nodes.extend(_ensure_entity_nodes(event_id, entities, nodes))
    return nodes, edges


def _extract_dns(
    event_id: str,
    evidence: Evidence,
    entities: list[tuple[str, str]],
) -> tuple[list[GraphNode], list[GraphEdge]]:
    """dns evidence → resolved (domain→ip), requested (host→domain)."""
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    hosts = [e for e in entities if e[0] == "host"]
    domains = [e for e in entities if e[0] == "domain"]
    ips = [e for e in entities if e[0] == "ip"]

    # resolved: domain → ip
    for dom in domains:
        for ip in ips:
            src_id = _make_node_id(event_id, dom[0], dom[1])
            tgt_id = _make_node_id(event_id, ip[0], ip[1])
            nodes.extend(
                [
                    _make_node(event_id, dom[0], dom[1], src_id),
                    _make_node(event_id, ip[0], ip[1], tgt_id),
                ]
            )
            edges.append(
                GraphEdge(
                    edge_id=_make_edge_id(
                        event_id, src_id, tgt_id, GraphRelationType.RESOLVED, evidence.evidence_id
                    ),
                    event_id=event_id,
                    source_node_id=src_id,
                    target_node_id=tgt_id,
                    relation_type=GraphRelationType.RESOLVED,
                    evidence_id=evidence.evidence_id,
                    occurred_at=evidence.timestamp,
                )
            )

    # requested: host → domain
    for host in hosts:
        for dom in domains:
            src_id = _make_node_id(event_id, host[0], host[1])
            tgt_id = _make_node_id(event_id, dom[0], dom[1])
            nodes.extend(
                [
                    _make_node(event_id, host[0], host[1], src_id),
                    _make_node(event_id, dom[0], dom[1], tgt_id),
                ]
            )
            edges.append(
                GraphEdge(
                    edge_id=_make_edge_id(
                        event_id, src_id, tgt_id, GraphRelationType.REQUESTED, evidence.evidence_id
                    ),
                    event_id=event_id,
                    source_node_id=src_id,
                    target_node_id=tgt_id,
                    relation_type=GraphRelationType.REQUESTED,
                    evidence_id=evidence.evidence_id,
                    occurred_at=evidence.timestamp,
                )
            )

    nodes.extend(_ensure_entity_nodes(event_id, entities, nodes))
    return nodes, edges


def _extract_default(
    event_id: str,
    evidence: Evidence,
    entities: list[tuple[str, str]],
) -> tuple[list[GraphNode], list[GraphEdge]]:
    """asset / threat_intel / false_positive_match → entity nodes only."""
    nodes: list[GraphNode] = []
    for etype, evalue in entities:
        nid = _make_node_id(event_id, etype, evalue)
        nodes.append(_make_node(event_id, etype, evalue, nid))
    return nodes, []


# --------------------------------------------------------------------------- #
# Helper
# --------------------------------------------------------------------------- #


def _make_node(
    event_id: str,
    entity_type: str,
    entity_value: str,
    node_id: str,
) -> GraphNode:
    return GraphNode(
        node_id=node_id,
        event_id=event_id,
        entity_type=entity_type,
        entity_value=entity_value,
    )


def _ensure_entity_nodes(
    event_id: str,
    entities: list[tuple[str, str]],
    existing_nodes: list[GraphNode],
) -> list[GraphNode]:
    """Return new GraphNode objects for any entity not yet represented in *existing_nodes*."""
    seen: set[tuple[str, str]] = {(n.entity_type, n.entity_value) for n in existing_nodes}
    extra: list[GraphNode] = []
    for etype, evalue in entities:
        key = (etype, evalue)
        if key not in seen:
            seen.add(key)
            nid = _make_node_id(event_id, etype, evalue)
            extra.append(_make_node(event_id, etype, evalue, nid))
    return extra


# --------------------------------------------------------------------------- #
# Source → extraction rule mapping
# --------------------------------------------------------------------------- #

EXTRACTION_RULES: dict[EvidenceSource, Any] = {
    EvidenceSource.IDENTITY: _extract_identity,
    EvidenceSource.ENDPOINT: _extract_endpoint,
    EvidenceSource.DATA_SECURITY: _extract_data_security,
    EvidenceSource.NETWORK_FLOW: _extract_network_flow,
    EvidenceSource.DNS: _extract_dns,
    EvidenceSource.ASSET: _extract_default,
    EvidenceSource.THREAT_INTEL: _extract_default,
    EvidenceSource.FALSE_POSITIVE_MATCH: _extract_default,
}


# --------------------------------------------------------------------------- #
# GraphBuilder
# --------------------------------------------------------------------------- #


class GraphBuilder:
    """Stateless evidence-to-graph transformer.

    ``build(evidence_list)`` iterates every Evidence record, dispatching to the
    per-source extraction rule after inferring entity types from related_entities
    string values. Nodes and edges are deduplicated by stable ID.
    """

    @staticmethod
    def build(evidence_list: list[Evidence]) -> tuple[list[GraphNode], list[GraphEdge]]:
        """Transform a list of Evidence into graph nodes and edges."""
        node_map: dict[str, GraphNode] = {}
        edge_map: dict[str, GraphEdge] = {}

        for evidence in evidence_list:
            entities = _infer_entity_types(evidence.related_entities, evidence.source)
            if not entities:
                continue

            rule = EXTRACTION_RULES.get(evidence.source, _extract_default)
            nodes, edges = rule(evidence.event_id, evidence, entities)

            for node in nodes:
                if node.node_id not in node_map:
                    node_map[node.node_id] = node
                else:
                    existing = node_map[node.node_id]
                    merged_props = {**existing.properties, **node.properties}
                    node_map[node.node_id] = existing.model_copy(
                        update={"properties": merged_props}
                    )

            for edge in edges:
                if edge.edge_id not in edge_map:
                    edge_map[edge.edge_id] = edge

        return list(node_map.values()), list(edge_map.values())
