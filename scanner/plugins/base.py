from typing import Dict, Iterable, List, Type

from scanner.core.capabilities import Capability
from scanner.plugins.contract import Module


class ModuleRegistry:
    """Simple registry for module plugins."""

    def __init__(self) -> None:
        self._modules: Dict[str, Module] = {}

    def register(self, module: Module) -> None:
        self._modules[module.name] = module

    def get(self, name: str) -> Module:
        return self._modules[name]

    def all(self) -> Dict[str, Module]:
        return dict(self._modules)

    def filter_by_capabilities(self, capabilities: Iterable[Capability]) -> Dict[str, Module]:
        allowed = set(capabilities)
        return {name: mod for name, mod in self._modules.items() if set(mod.required_capabilities) <= allowed}


class BaseModule(Module):
    """Helper base with name/description metadata."""

    name: str = "base"
    description: str = ""
    version: str = "0.1.0"
    required_capabilities: List[Capability] = []

    def __repr__(self) -> str:
        return f"<Module {self.name}>"
