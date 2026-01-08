from __future__ import annotations

from dataclasses import dataclass
from typing import AsyncIterator, Callable, Protocol

from sqlmodel import Session

from scanner.config import Settings
from scanner.core.capabilities import Capability
from scanner.core.events import Event
from scanner.core.models import Scan, StorageMode
from scanner.core.storage import StorageBackend


@dataclass(frozen=True)
class ModuleContext:
    """Shared, read-only context passed to module runs."""

    settings: Settings
    session_factory: Callable[[], Session]
    storage_backend: StorageBackend
    storage_mode_default: StorageMode


class Module(Protocol):
    """Plugin contract for scan modules."""

    name: str
    description: str
    version: str
    required_capabilities: list[Capability]

    async def run(self, scan: Scan, context: ModuleContext) -> AsyncIterator[Event]:
        ...
