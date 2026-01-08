from pathlib import Path
from typing import Dict, Optional

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


def store_body(
    scan_id: str,
    fetch_id: str,
    body: Optional[bytes],
    storage_mode: StorageMode,
    artifact_base: str,
) -> Optional[str]:
    """Persist body according to storage mode. Returns artifact path if stored."""
    if not body or storage_mode == StorageMode.NONE:
        return None
    processed = sample_body(redact_body(body)) if storage_mode == StorageMode.SAMPLED else redact_body(body)
    base = Path(artifact_base).expanduser()
    base.mkdir(parents=True, exist_ok=True)
    out_path = base / f"{scan_id}_{fetch_id}.bin"
    out_path.write_bytes(processed)
    return str(out_path)
