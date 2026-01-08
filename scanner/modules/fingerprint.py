from scanner.core.capabilities import Capability
from scanner.core.events import TechComponentEvent
from scanner.core.models import Confidence
from scanner.plugins.base import BaseModule


class FingerprintModule(BaseModule):
    name = "fingerprint"
    description = "Detects stack components from responses."
    required_capabilities = [Capability.NET_PASSIVE]

    async def run(self, scan):
        yield TechComponentEvent(
            module=self.name,
            scan_id=scan.id,
            name="http.service",
            version=None,
            cpe=None,
            confidence=Confidence.LOW.value,
        )
