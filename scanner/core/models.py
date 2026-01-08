from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


def _ts() -> datetime:
    return datetime.utcnow()


class StorageMode(str, Enum):
    NONE = "none"
    SAMPLED = "sampled"
    FULL = "full"


class FindingStatus(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    SOFT_DELETED = "soft_deleted"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AuditAction(str, Enum):
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    MODULE_RUN = "module.run"
    EXPORT = "export.generated"
    EXCEPTION_CREATED = "exception.created"
    EXCEPTION_EXPIRED = "exception.expired"
    RECHECK = "recheck.triggered"


class BaseTable(SQLModel):
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    created_at: datetime = Field(default_factory=_ts)
    updated_at: datetime = Field(default_factory=_ts)


class Target(BaseTable, table=True):
    base_url: str
    environment: str = Field(default="unknown", description="Env tag, e.g. prod/stage.")
    auth_profiles: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Named auth profiles (headers/cookies/flows).",
        sa_column=Column(JSON, nullable=False),
    )


class Scan(BaseTable, table=True):
    target_id: str = Field(foreign_key="target.id")
    mode: str
    profile_name: str
    profile_capabilities: List[str] = Field(
        default_factory=list, sa_column=Column(JSON, nullable=False)
    )
    status: str = Field(default="pending")
    baseline_scan_id: Optional[str] = Field(default=None, foreign_key="scan.id")
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class Endpoint(BaseTable, table=True):
    scan_id: str = Field(foreign_key="scan.id")
    method: str
    url: str
    params_hash: str
    source: str = Field(description="discovery|openapi|zap|manual")
    first_seen: datetime = Field(default_factory=_ts)
    last_seen: datetime = Field(default_factory=_ts)


class Fetch(BaseTable, table=True):
    endpoint_id: str = Field(foreign_key="endpoint.id")
    request: Dict[str, Any] = Field(
        default_factory=dict, sa_column=Column(JSON, nullable=False)
    )
    response_meta: Dict[str, Any] = Field(
        default_factory=dict, sa_column=Column(JSON, nullable=False)
    )
    storage_mode: StorageMode = Field(default=StorageMode.SAMPLED)
    redaction_version: str = Field(default="v1")
    body_path: Optional[str] = None
    body_hash: Optional[str] = None


class Evidence(BaseTable, table=True):
    fetch_id: Optional[str] = Field(default=None, foreign_key="fetch.id")
    kind: str
    snippet: str
    location: str = Field(description="Where in the response/request this evidence was found.")
    hash: str
    details: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))


class TechComponent(BaseTable, table=True):
    endpoint_id: str = Field(foreign_key="endpoint.id")
    name: str
    version: Optional[str] = None
    cpe: Optional[str] = None
    confidence: Confidence = Field(default=Confidence.MEDIUM)
    evidence_ids: List[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))


class CVECandidate(BaseTable, table=True):
    cpe: str
    cve_id: str
    source: str = Field(default="nvd")
    confidence: Confidence = Field(default=Confidence.LOW)
    status: str = Field(default="candidate")
    linked_component_id: Optional[str] = Field(default=None, foreign_key="techcomponent.id")


class Finding(BaseTable, table=True):
    dedupe_key: str = Field(index=True)
    type: str
    title: str
    description: Optional[str] = None
    severity: str
    confidence: Confidence = Field(default=Confidence.MEDIUM)
    status: FindingStatus = Field(default=FindingStatus.OPEN)
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    first_seen: datetime = Field(default_factory=_ts)
    last_seen: datetime = Field(default_factory=_ts)
    fixed_at: Optional[datetime] = None
    evidence_ids: List[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    source_module: str


class ExceptionRecord(BaseTable, table=True):
    finding_key: str = Field(index=True)
    expires_at: datetime
    approver: str
    ticket: str
    status: str = Field(default="approved")
    reason: Optional[str] = None
    owner: Optional[str] = None


class AuditEvent(BaseTable, table=True):
    actor: str
    action: AuditAction
    scan_id: Optional[str] = Field(default=None, foreign_key="scan.id")
    params: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    immutable: bool = Field(default=True)
