"""Settings loaded from environment (pydantic-settings). No secrets may have
code defaults — keys either come from env or the app refuses to start."""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"), env_file_encoding="utf-8", extra="ignore"
    )

    env: Literal["demo", "dev"] = "demo"

    # --- Core ---
    database_url: str = "postgresql+asyncpg://cleartrade:cleartrade@localhost:5432/cleartrade"
    sync_database_url: str = "postgresql+psycopg://cleartrade:cleartrade@localhost:5432/cleartrade"
    redis_url: str = "redis://localhost:6379/0"

    # --- LiteLLM proxy ---
    litellm_base_url: str = "http://localhost:4000"
    litellm_virtual_key: str  # backend key with spend cap; no default = fail fast
    litellm_timeout_s: float = 35.0

    # --- Auth / crypto ---
    approval_signing_key: str = ""  # deprecated; signers must keep private keys client-side
    approval_public_keys_json: str = "{}"  # approver_id -> base64 raw Ed25519 public key

    # --- Budgets (kill switches) ---
    budget_max_steps: int = 64
    budget_max_tokens_per_deal: int = 400_000
    budget_max_cost_minor_per_deal: int = 500_00  # USD minor units ($500) hard ceiling

    # --- Payout ---
    payout_mode: Literal["sandbox"] = "sandbox"

    # --- Observability ---
    otel_endpoint: str | None = None
    langfuse_public_key: str | None = None
    langfuse_secret_key: str | None = None
    langfuse_host: str | None = None

    # --- Uploads ---
    upload_max_bytes: int = 10 * 1024 * 1024
    upload_allowed_types: tuple[str, ...] = ("application/pdf", "image/jpeg", "image/png")

    # --- Optional live-service flags for tests ---
    feature_wechat: bool = False

    otel_exporter_otlp_endpoint: str | None = Field(
        default=None, alias="OTEL_EXPORTER_OTLP_ENDPOINT"
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
