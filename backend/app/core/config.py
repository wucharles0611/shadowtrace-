"""Application settings (pydantic-settings)."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration. Defaults target Docker Compose service names."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    app_version: str = Field(default="0.1.0", alias="APP_VERSION")
    app_env: str = Field(default="development", alias="APP_ENV")

    database_url: str = Field(
        default="postgresql+asyncpg://shadowtrace:shadowtrace@postgres:5432/shadowtrace",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://redis:6379/0", alias="REDIS_URL")

    source_mode: str = Field(default="mock_xdr", alias="SOURCE_MODE")
    source_read_only: bool = Field(default=True, alias="SOURCE_READ_ONLY")

    tool_mode: str = Field(default="mock", alias="TOOL_MODE")

    disposition_mode: str = Field(default="mock_xdr", alias="DISPOSITION_MODE")
    disposition_adapter_kind: str = Field(default="mock", alias="DISPOSITION_ADAPTER_KIND")
    disposition_base_url: str = Field(default="", alias="DISPOSITION_BASE_URL")
    disposition_credential_ref: str = Field(default="", alias="DISPOSITION_CREDENTIAL_REF")

    allow_xdr_writeback: bool = Field(default=False, alias="ALLOW_XDR_WRITEBACK")
    allow_live_side_effects: bool = Field(default=False, alias="ALLOW_LIVE_SIDE_EFFECTS")
    writeback_field_allowlist: str = Field(
        default="status,disposition,comment",
        alias="WRITEBACK_FIELD_ALLOWLIST",
    )
    writeback_max_retries: int = Field(default=5, alias="WRITEBACK_MAX_RETRIES")
    simulation_enabled: bool = Field(default=True, alias="SIMULATION_ENABLED")

    llm_mode: str = Field(default="mock", alias="LLM_MODE")
    llm_api_base_url: str = Field(default="", alias="LLM_API_BASE_URL")
    llm_api_key: str = Field(default="", alias="LLM_API_KEY")
    llm_primary_model: str = Field(default="mock-model", alias="LLM_PRIMARY_MODEL")
    llm_fallback_models: str = Field(default="", alias="LLM_FALLBACK_MODELS")
    llm_timeout_seconds: int = Field(default=30, alias="LLM_TIMEOUT_SECONDS")

    budget_enabled: bool = Field(default=True, alias="BUDGET_ENABLED")
    global_token_budget: int = Field(default=1_000_000, alias="GLOBAL_TOKEN_BUDGET")
    event_token_budget: int = Field(default=100_000, alias="EVENT_TOKEN_BUDGET")
    event_cost_budget_usd: float = Field(default=5.0, alias="EVENT_COST_BUDGET_USD")
    per_agent_token_cap: int = Field(default=20_000, alias="PER_AGENT_TOKEN_CAP")
    quality_judge_enabled: bool = Field(default=False, alias="QUALITY_JUDGE_ENABLED")
    guardrail_mode: str = Field(default="enforce", alias="GUARDRAIL_MODE")
    wm_strict: bool = Field(default=True, alias="WM_STRICT")

    orchestration_mode: str = Field(default="graph", alias="ORCHESTRATION_MODE")
    react_enabled: bool = Field(default=False, alias="REACT_ENABLED")
    task_mode: str = Field(default="background", alias="TASK_MODE")
    celery_broker_url: str = Field(default="redis://redis:6379/1", alias="CELERY_BROKER_URL")
    approval_timeout_minutes: int = Field(default=30, alias="APPROVAL_TIMEOUT_MINUTES")


@lru_cache
def get_settings() -> Settings:
    """Return cached Settings singleton for FastAPI dependency injection."""
    return Settings()
