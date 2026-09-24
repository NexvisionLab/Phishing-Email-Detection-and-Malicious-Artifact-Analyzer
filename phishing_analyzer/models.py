from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class Finding:
    code: str
    title: str
    severity: str
    points: int
    evidence: str
    source: str
    status: str = "observed"


@dataclass(slots=True)
class LinkResult:
    display_url: str
    normalized_url: str
    host: str
    score: int = 0
    risk: str = "low"
    findings: list[Finding] = field(default_factory=list)
    reputation: dict[str, Any] = field(default_factory=dict)
    registrable_domain: str = ""
    rank_score: int = 0
    selected_for_deep_inspection: bool = True
    osint: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AttachmentResult:
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    detected_type: str
    score: int = 0
    risk: str = "low"
    findings: list[Finding] = field(default_factory=list)
    extracted_urls: list[str] = field(default_factory=list)
    qr: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ScoreDimensions:
    sender_authenticity: int = 0
    message_intent: int = 0
    destination_risk: int = 0
    payload_risk: int = 0


@dataclass(slots=True)
class AnalysisResult:
    version: str
    input_type: str
    score: int
    risk: str
    classification: str
    confidence: str
    summary: str
    findings: list[Finding]
    links: list[LinkResult]
    links_found: int
    links_checked: int
    limitations: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)
    attachments: list[AttachmentResult] = field(default_factory=list)
    dimensions: ScoreDimensions = field(default_factory=ScoreDimensions)
    evidence_status: dict[str, str] = field(default_factory=dict)
    analyst_disposition: str = "unreviewed"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
