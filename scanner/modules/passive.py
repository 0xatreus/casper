from scanner.core.capabilities import Capability
from scanner.core.events import EvidenceEvent, FindingEvent
from scanner.core.models import Confidence
from scanner.plugins.base import BaseModule


class PassiveModule(BaseModule):
    name = "passive_checks"
    description = "Header/TLS/info-leak passive checks."
    required_capabilities = [Capability.NET_PASSIVE]

    async def run(self, scan, context):
        # Placeholder: emit a low-severity informational finding for demo.
        dedupe_key = f"info::passive::baseline::{scan.target_id}"
        evidence = EvidenceEvent(
            module=self.name,
            scan_id=scan.id,
            kind="note",
            snippet="Passive checks executed (placeholder).",
            location="n/a",
            hash=dedupe_key,
        )
        yield evidence
        yield FindingEvent(
            module=self.name,
            scan_id=scan.id,
            title="Passive checks placeholder",
            description="Placeholder finding emitted by the passive checks module.",
            dedupe_key=dedupe_key,
            type="informational.passive_placeholder",
            severity="info",
            confidence=Confidence.LOW.value,
            evidence_ids=None,
            source_module=self.name,
            remediation="Replace placeholder checks with real passive validation and evidence.",
            references=[],
        )
