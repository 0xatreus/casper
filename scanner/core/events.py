from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class Event(BaseModel):
    module: str
    scan_id: str


class EndpointDiscovered(Event):
    url: str
    method: str = "GET"
    params_hash: str = Field(default="na")
    source: str = "discovery"


class EvidenceEvent(Event):
    fetch_id: Optional[str] = None
    kind: str
    snippet: str
    location: str
    hash: str
    details: Dict[str, Any] = Field(default_factory=dict)


class FindingEvent(Event):
    title: str
    description: Optional[str] = None
    dedupe_key: str
    type: str
    severity: str
    confidence: str = "medium"
    evidence_ids: Optional[list[str]] = None
    source_module: str
    remediation: Optional[str] = None
    references: list[str] = Field(default_factory=list)
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None


class FetchEvent(Event):
    fetch_id: str
    endpoint_id: str
    request: Dict[str, Any] = Field(default_factory=dict)
    response_meta: Dict[str, Any] = Field(default_factory=dict)
    body: Optional[bytes] = None
    storage_mode: Optional[str] = None


class TechComponentEvent(Event):
    endpoint_id: Optional[str] = None
    name: str
    version: Optional[str] = None
    cpe: Optional[str] = None
    confidence: str = "medium"


class CVECandidateEvent(Event):
    cpe: str
    cve_id: str
    source: str = "nvd"
    confidence: str = "low"
    linked_component_id: Optional[str] = None


class RecordPack(Event):
    """Replayable request/response pairs captured in record-only mode."""

    requests: list[Dict] = Field(default_factory=list)
