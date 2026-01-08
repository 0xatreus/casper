from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings

from scanner.core.models import StorageMode


class Settings(BaseSettings):
    app_name: str = Field("scanner", description="Service identifier for logging/metrics.")
    database_url: str = Field(
        "postgresql+psycopg://scanner:scanner@localhost:5432/scanner",
        description="Postgres connection string for SQLModel.",
    )
    redis_url: str = Field("redis://localhost:6379/0", description="Broker/cache backend.")
    object_store_base: str = Field(
        "file:///tmp/scanner-artifacts",
        description="Base URI for response body/object storage.",
    )
    storage_mode_default: StorageMode = Field(
        StorageMode.SAMPLED,
        description="Default response body storage mode (none/sampled/full).",
    )
    record_only_default: bool = Field(
        False, description="If true, active modules default to record-only."
    )

    class Config:
        env_prefix = "SCANNER_"
        case_sensitive = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
