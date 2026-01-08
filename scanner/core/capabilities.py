from enum import Enum
from typing import Iterable, Set
from pydantic import BaseModel, Field


class Capability(str, Enum):
    NET_PASSIVE = "net.passive"
    NET_ACTIVE_SAFE = "net.active-safe"
    NET_INTRUSIVE = "net.intrusive"
    ZAP_CONTROL = "zap.control"
    RECORD_ONLY = "record-only"
    PII_READ = "pii.read"
    PII_STORE_FULL = "pii.store-full"
    PII_STORE_SAMPLED = "pii.store-sampled"
    PII_REDACT = "pii.redact"
    RECHECK = "recheck"
    EXCEPTION_MANAGE = "exception.manage"


class CapabilityProfile(BaseModel):
    name: str
    mode: str = Field(..., description="High-level scan mode label (passive/active/intrusive).")
    capabilities: Set[Capability]


class CapabilityError(PermissionError):
    """Raised when a module attempts to run without a granted capability."""


PASSIVE_PROFILE = CapabilityProfile(
    name="passive",
    mode="passive",
    capabilities={
        Capability.NET_PASSIVE,
        Capability.PII_STORE_SAMPLED,
        Capability.PII_REDACT,
    },
)

ACTIVE_PROFILE = CapabilityProfile(
    name="active",
    mode="active",
    capabilities={
        Capability.NET_PASSIVE,
        Capability.NET_ACTIVE_SAFE,
        Capability.RECORD_ONLY,
        Capability.PII_STORE_SAMPLED,
        Capability.PII_REDACT,
    },
)

INTRUSIVE_PROFILE = CapabilityProfile(
    name="intrusive",
    mode="intrusive",
    capabilities={
        Capability.NET_PASSIVE,
        Capability.NET_ACTIVE_SAFE,
        Capability.NET_INTRUSIVE,
        Capability.RECORD_ONLY,
        Capability.PII_STORE_SAMPLED,
        Capability.PII_REDACT,
    },
)


def ensure_capabilities(required: Iterable[Capability], granted: Set[Capability]) -> None:
    missing = set(required) - set(granted)
    if missing:
        raise CapabilityError(f"Missing capabilities: {', '.join(sorted(missing))}")
