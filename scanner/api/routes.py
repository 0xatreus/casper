import asyncio
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import select

from scanner.core.capabilities import ACTIVE_PROFILE, INTRUSIVE_PROFILE, PASSIVE_PROFILE
from scanner.core.db import session_scope
from scanner.core.models import AuditEvent, Evidence, ExceptionRecord, Finding, Scan, Target
from scanner.core.orchestrator import Orchestrator
from scanner.modules import build_registry
from scanner.config import get_settings

router = APIRouter()

settings = get_settings()
module_registry = build_registry()
orchestrator = Orchestrator(session_scope, module_registry.all(), settings)


class TargetCreate(BaseModel):
    base_url: str
    environment: str = Field(default="unknown")
    auth_profiles: Dict[str, Dict] = Field(default_factory=dict)


@router.get("/targets", response_model=List[Target])
def list_targets() -> List[Target]:
    with session_scope() as session:
        return session.exec(select(Target)).all()


@router.get("/targets/{target_id}", response_model=Target)
def get_target(target_id: str) -> Target:
    with session_scope() as session:
        target = session.get(Target, target_id)
        if not target:
            raise HTTPException(status_code=404, detail="target not found")
        return target


@router.post("/targets", response_model=Target)
def create_target(payload: TargetCreate) -> Target:
    with session_scope() as session:
        target = Target(
            base_url=payload.base_url,
            environment=payload.environment,
            auth_profiles=payload.auth_profiles,
        )
        session.add(target)
        session.commit()
        session.refresh(target)
        return target


class ScanRequest(BaseModel):
    target_id: str
    mode: str = Field(pattern="^(passive|active|intrusive)$")
    modules: Optional[List[str]] = None
    baseline_scan_id: Optional[str] = None


class ScanResponse(BaseModel):
    scan: Scan
    modules: List[str]


@router.get("/scans", response_model=List[Scan])
def list_scans() -> List[Scan]:
    with session_scope() as session:
        return session.exec(select(Scan)).all()


@router.get("/scans/{scan_id}", response_model=Scan)
def get_scan(scan_id: str) -> Scan:
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="scan not found")
        return scan


@router.post("/scans", response_model=ScanResponse)
async def start_scan(payload: ScanRequest, background_tasks: BackgroundTasks) -> ScanResponse:
    profile = {
        "passive": PASSIVE_PROFILE,
        "active": ACTIVE_PROFILE,
        "intrusive": INTRUSIVE_PROFILE,
    }.get(payload.mode)
    if not profile:
        raise HTTPException(status_code=400, detail="invalid mode")

    module_names = payload.modules or list(module_registry.all().keys())
    for name in module_names:
        if name not in module_registry.all():
            raise HTTPException(status_code=400, detail=f"unknown module {name}")

    scan = orchestrator.create_scan(
        target_id=payload.target_id, profile=profile, baseline_scan_id=payload.baseline_scan_id
    )

    async def _kickoff():
        await orchestrator.run_scan(scan, module_names)

    # Create the task on the running loop; BackgroundTasks executes in a thread where no loop exists.
    asyncio.create_task(_kickoff())
    return ScanResponse(scan=scan, modules=module_names)


@router.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@router.get("/findings", response_model=List[Finding])
def list_findings() -> List[Finding]:
    with session_scope() as session:
        return session.exec(select(Finding)).all()


@router.get("/findings/{finding_id}", response_model=Finding)
def get_finding(finding_id: str) -> Finding:
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="finding not found")
        return finding


@router.get("/evidence", response_model=List[Evidence])
def list_evidence() -> List[Evidence]:
    with session_scope() as session:
        return session.exec(select(Evidence)).all()


@router.get("/evidence/{evidence_id}", response_model=Evidence)
def get_evidence(evidence_id: str) -> Evidence:
    with session_scope() as session:
        evidence = session.get(Evidence, evidence_id)
        if not evidence:
            raise HTTPException(status_code=404, detail="evidence not found")
        return evidence


@router.get("/audit", response_model=List[AuditEvent])
def list_audit_events() -> List[AuditEvent]:
    with session_scope() as session:
        return session.exec(select(AuditEvent)).all()


@router.get("/audit/{event_id}", response_model=AuditEvent)
def get_audit_event(event_id: str) -> AuditEvent:
    with session_scope() as session:
        audit = session.get(AuditEvent, event_id)
        if not audit:
            raise HTTPException(status_code=404, detail="audit event not found")
        return audit


class ExceptionCreate(BaseModel):
    finding_key: str
    expires_at: datetime
    approver: str
    ticket: str
    reason: Optional[str] = None
    owner: Optional[str] = None


@router.get("/exceptions", response_model=List[ExceptionRecord])
def list_exceptions() -> List[ExceptionRecord]:
    with session_scope() as session:
        return session.exec(select(ExceptionRecord)).all()


@router.get("/exceptions/{exception_id}", response_model=ExceptionRecord)
def get_exception(exception_id: str) -> ExceptionRecord:
    with session_scope() as session:
        record = session.get(ExceptionRecord, exception_id)
        if not record:
            raise HTTPException(status_code=404, detail="exception not found")
        return record


@router.post("/exceptions", response_model=ExceptionRecord)
def create_exception(payload: ExceptionCreate) -> ExceptionRecord:
    with session_scope() as session:
        record = ExceptionRecord(
            finding_key=payload.finding_key,
            expires_at=payload.expires_at,
            approver=payload.approver,
            ticket=payload.ticket,
            reason=payload.reason,
            owner=payload.owner,
        )
        session.add(record)
        session.commit()
        session.refresh(record)
        return record
