import asyncio
from datetime import datetime
from typing import Callable, Dict, Iterable, List, Optional, Type

from sqlmodel import Session, select

from .capabilities import Capability, CapabilityProfile, ensure_capabilities
from .events import (
    CVECandidateEvent,
    EndpointDiscovered,
    Event,
    EvidenceEvent,
    FindingEvent,
    RecordPack,
    TechComponentEvent,
)
from .models import (
    AuditAction,
    CVECandidate,
    Endpoint,
    Evidence,
    Finding,
    Confidence,
    FindingStatus,
    Scan,
    Target,
    TechComponent,
)
from .audit import record_audit_event


class Orchestrator:
    """Builds and executes scan plans against enabled modules."""

    def __init__(self, session_factory, module_registry: Dict[str, "Module"]):
        self._session_factory = session_factory
        self._modules = module_registry

    def create_scan(self, target_id: str, profile: CapabilityProfile, baseline_scan_id: Optional[str] = None) -> Scan:
        with self._session_factory() as session:
            target = session.exec(select(Target).where(Target.id == target_id)).one()
            scan = Scan(
                target_id=target.id,
                mode=profile.mode,
                profile_name=profile.name,
                profile_capabilities=[c.value for c in profile.capabilities],
                baseline_scan_id=baseline_scan_id,
                status="queued",
            )
            session.add(scan)
            session.commit()
            session.refresh(scan)
            record_audit_event(session, actor="system", action=AuditAction.SCAN_STARTED, scan_id=scan.id)
            return scan

    async def run_scan(self, scan: Scan, enabled_modules: Iterable[str]) -> None:
        await self._set_scan_status(scan.id, "running")
        tasks: List[asyncio.Task] = []
        for name in enabled_modules:
            module = self._modules[name]
            ensure_capabilities(module.required_capabilities, set(Capability(c) for c in scan.profile_capabilities))
            tasks.append(asyncio.create_task(self._run_module(module, scan)))
        try:
            await asyncio.gather(*tasks)
        except Exception:
            await self._set_scan_status(scan.id, "failed")
            raise
        else:
            await self._set_scan_status(scan.id, "completed")

    async def _run_module(self, module: "Module", scan: Scan) -> None:
        async for event in module.run(scan):
            self._persist_event(event)

    def _persist_event(self, event: Event) -> None:
        """Persist module events to the DB and emit audit records."""
        with self._session_factory() as session:
            self._handle_event(session, event)
            record_audit_event(
                session,
                actor=event.module,
                action=AuditAction.MODULE_RUN,
                scan_id=event.scan_id,
                params={"event": event.model_dump()},
            )

    def _handle_event(self, session: Session, event: Event) -> None:
        handler_map: Dict[Type[Event], Callable[[Session, Event], Optional[object]]] = {
            EndpointDiscovered: self._save_endpoint,
            EvidenceEvent: self._save_evidence,
            FindingEvent: self._save_finding,
            TechComponentEvent: self._save_tech_component,
            CVECandidateEvent: self._save_cve_candidate,
            RecordPack: self._save_record_pack,
        }
        for event_type, handler in handler_map.items():
            if isinstance(event, event_type):
                handler(session, event)
                break

    def _save_endpoint(self, session: Session, event: EndpointDiscovered) -> Endpoint:
        stmt = select(Endpoint).where(
            Endpoint.scan_id == event.scan_id,
            Endpoint.url == event.url,
            Endpoint.method == event.method,
            Endpoint.params_hash == event.params_hash,
        )
        endpoint = session.exec(stmt).first()
        if endpoint:
            endpoint.last_seen = datetime.utcnow()
        else:
            now = datetime.utcnow()
            endpoint = Endpoint(
                scan_id=event.scan_id,
                method=event.method,
                url=event.url,
                params_hash=event.params_hash,
                source=event.source,
                first_seen=now,
                last_seen=now,
            )
            session.add(endpoint)
        session.commit()
        session.refresh(endpoint)
        return endpoint

    def _save_evidence(self, session: Session, event: EvidenceEvent) -> Evidence:
        evidence = Evidence(
            fetch_id=event.fetch_id,
            kind=event.kind,
            snippet=event.snippet,
            location=event.location,
            hash=event.hash,
        )
        session.add(evidence)
        session.commit()
        session.refresh(evidence)
        return evidence

    def _save_finding(self, session: Session, event: FindingEvent) -> Finding:
        stmt = select(Finding).where(Finding.dedupe_key == event.dedupe_key)
        finding = session.exec(stmt).first()
        now = datetime.utcnow()
        confidence = Confidence(event.confidence)
        if finding:
            finding.last_seen = now
            finding.severity = event.severity
            finding.confidence = confidence
            finding.source_module = event.source_module
            finding.evidence_ids = event.evidence_ids or []
        else:
            finding = Finding(
                dedupe_key=event.dedupe_key,
                type=event.type,
                severity=event.severity,
                confidence=confidence,
                status=FindingStatus.OPEN,
                first_seen=now,
                last_seen=now,
                evidence_ids=event.evidence_ids or [],
                source_module=event.source_module,
            )
            session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding

    def _save_tech_component(self, session: Session, event: TechComponentEvent) -> TechComponent:
        if event.endpoint_id is None:
            # Placeholder data has no endpoint context; skip persisting to avoid FK violations.
            return None
        stmt = select(TechComponent).where(
            TechComponent.endpoint_id == event.endpoint_id,
            TechComponent.name == event.name,
            TechComponent.version == event.version,
            TechComponent.cpe == event.cpe,
        )
        component = session.exec(stmt).first()
        confidence = Confidence(event.confidence)
        if component:
            component.confidence = confidence
        else:
            component = TechComponent(
                endpoint_id=event.endpoint_id,
                name=event.name,
                version=event.version,
                cpe=event.cpe,
                confidence=confidence,
            )
            session.add(component)
        session.commit()
        session.refresh(component)
        return component

    def _save_cve_candidate(self, session: Session, event: CVECandidateEvent) -> CVECandidate:
        stmt = select(CVECandidate).where(
            CVECandidate.cpe == event.cpe,
            CVECandidate.cve_id == event.cve_id,
            CVECandidate.source == event.source,
        )
        candidate = session.exec(stmt).first()
        confidence = Confidence(event.confidence)
        if candidate:
            candidate.confidence = confidence
            candidate.linked_component_id = event.linked_component_id
        else:
            candidate = CVECandidate(
                cpe=event.cpe,
                cve_id=event.cve_id,
                source=event.source,
                confidence=confidence,
                linked_component_id=event.linked_component_id,
            )
            session.add(candidate)
        session.commit()
        session.refresh(candidate)
        return candidate

    def _save_record_pack(self, session: Session, event: RecordPack) -> None:
        # No dedicated storage yet; keep audit for traceability.
        return None

    async def _set_scan_status(self, scan_id: str, status: str) -> None:
        with self._session_factory() as session:
            scan = session.get(Scan, scan_id)
            if scan:
                scan.status = status
                now = datetime.utcnow()
                if status == "running":
                    scan.started_at = now
                if status in {"completed", "failed"}:
                    scan.finished_at = now
                session.add(scan)
                session.commit()


class Module:
    """Protocol for modules. Implemented in scanner.modules.*"""

    name: str
    required_capabilities: List[Capability]

    async def run(self, scan: Scan):
        raise NotImplementedError
