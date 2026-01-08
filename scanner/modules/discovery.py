from scanner.core.capabilities import Capability
from scanner.core.events import EndpointDiscovered
from scanner.core.models import Target
from scanner.plugins.base import BaseModule
from scanner.core.db import session_scope


class DiscoveryModule(BaseModule):
    name = "discovery"
    description = "Lightweight crawler/API discovery stub."
    required_capabilities = [Capability.NET_PASSIVE]

    async def run(self, scan) -> EndpointDiscovered:
        with session_scope() as session:
            target = session.get(Target, scan.target_id)
        if not target:
            return
        yield EndpointDiscovered(
            module=self.name,
            scan_id=scan.id,
            url=target.base_url,
            method="GET",
            params_hash="base",
            source="discovery",
        )
