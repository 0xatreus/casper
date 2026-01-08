from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Protocol
from urllib.parse import urlparse

from .models import StorageMode

MAX_SAMPLE_BYTES = 4096


def redact_body(body: bytes) -> bytes:
    """Very small placeholder redaction that strips common token shapes."""
    replacements: Dict[bytes, bytes] = {
        b"Bearer ": b"Bearer [redacted]",
        b"token=": b"token=[redacted]",
        b"Authorization": b"Authorization: [redacted]",
    }
    redacted = body
    for needle, repl in replacements.items():
        redacted = redacted.replace(needle, repl)
    return redacted


def sample_body(body: bytes) -> bytes:
    if len(body) <= MAX_SAMPLE_BYTES:
        return body
    return body[:MAX_SAMPLE_BYTES]


class StorageBackend(Protocol):
    def store_body(
        self,
        scan_id: str,
        fetch_id: str,
        body: Optional[bytes],
        storage_mode: StorageMode,
    ) -> Optional[str]:
        ...


@dataclass(frozen=True)
class LocalStorageBackend:
    base_path: Path

    def store_body(
        self,
        scan_id: str,
        fetch_id: str,
        body: Optional[bytes],
        storage_mode: StorageMode,
    ) -> Optional[str]:
        if not body or storage_mode == StorageMode.NONE:
            return None
        processed = sample_body(redact_body(body)) if storage_mode == StorageMode.SAMPLED else redact_body(body)
        self.base_path.mkdir(parents=True, exist_ok=True)
        out_path = self.base_path / f"{scan_id}_{fetch_id}.bin"
        out_path.write_bytes(processed)
        return str(out_path)


def get_storage_backend(uri: str) -> StorageBackend:
    parsed = urlparse(uri)
    if parsed.scheme in {"", "file"}:
        base = Path(parsed.path or uri).expanduser()
        return LocalStorageBackend(base_path=base)
    raise NotImplementedError(f"Unsupported object store scheme: {parsed.scheme}")
