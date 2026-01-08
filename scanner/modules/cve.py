from scanner.core.capabilities import Capability
from scanner.core.events import CVECandidateEvent
from scanner.core.models import Confidence
from scanner.plugins.base import BaseModule


class CVECorrelatorModule(BaseModule):
    name = "cve_correlator"
    description = "Maps tech components to CVE candidates."
    required_capabilities = [Capability.NET_PASSIVE]

    async def run(self, scan):
        # Placeholder candidate to illustrate flow.
        yield CVECandidateEvent(
            module=self.name,
            scan_id=scan.id,
            cpe="cpe:/a:example:placeholder:0.0.0",
            cve_id="CVE-0000-0000",
            source="placeholder",
            confidence=Confidence.LOW.value,
            linked_component_id=None,
        )
