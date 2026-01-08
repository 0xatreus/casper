import logging
from typing import Dict, Optional

import structlog
from sqlmodel import Session

from .models import AuditAction, AuditEvent

logger = structlog.get_logger(__name__)


def record_audit_event(
    session: Session,
    actor: str,
    action: AuditAction,
    scan_id: Optional[str] = None,
    params: Optional[Dict] = None,
) -> AuditEvent:
    event = AuditEvent(actor=actor, action=action, scan_id=scan_id, params=params or {})
    session.add(event)
    session.commit()
    session.refresh(event)
    logger.info("audit_event", actor=actor, action=action, scan_id=scan_id, params=params)
    return event
