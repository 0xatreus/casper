from scanner.core.capabilities import Capability
from scanner.core.events import RecordPack
from scanner.plugins.base import BaseModule


class ManualExportModule(BaseModule):
    name = "manual_export"
    description = "Packages scan artifacts for human testers."
    required_capabilities = [Capability.NET_PASSIVE]

    async def run(self, scan):
        # Placeholder: emit an empty record pack.
        yield RecordPack(module=self.name, scan_id=scan.id, requests=[])
