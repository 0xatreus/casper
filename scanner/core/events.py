from typing import Dict, Optional
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


class FindingEvent(Event):
    dedupe_key: str
    type: str
    severity: str
    confidence: str = "medium"
    evidence_ids: Optional[list[str]] = None
    source_module: str


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
