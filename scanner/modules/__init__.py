"""Module implementations and registry bootstrap."""

from scanner.plugins.base import ModuleRegistry

from .discovery import DiscoveryModule
from .passive import PassiveModule
from .fingerprint import FingerprintModule
from .cve import CVECorrelatorModule
from .manual_export import ManualExportModule


def build_registry() -> ModuleRegistry:
    registry = ModuleRegistry()
    for module_cls in [
        DiscoveryModule,
        PassiveModule,
        FingerprintModule,
        CVECorrelatorModule,
        ManualExportModule,
    ]:
        registry.register(module_cls())
    return registry
