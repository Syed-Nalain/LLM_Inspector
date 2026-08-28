"""
Central configuration for LLM Inspector.

Loads from environment variables / a .env file. The LLM API key must
always come from the user (env var, .env file, or an explicit --api-key
flag on the CLI). Supports multiple LLM providers as the reasoning brain:
Anthropic (Claude), OpenAI, Google Gemini, or Ollama (local).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Budget:
    """
    Hard limits on a single scan. This is what stops the agent from doing
    "attack, attack, attack, attack, attack, ..." forever -- see
    architecture doc, component (6) "Give the agent a testing budget".
    """

    max_seconds: int = int(os.getenv("LLM_INSPECTOR_MAX_SCAN_SECONDS", "1200"))
    max_tool_calls: int = int(os.getenv("LLM_INSPECTOR_MAX_TOOL_CALLS", "150"))
    max_usd: float = float(os.getenv("LLM_INSPECTOR_MAX_USD", "5.00"))
    max_probes_per_tool: dict[str, int] = field(
        default_factory=lambda: {
            "garak": 100,
            "pyrit": 50,
            "promptfoo": 200,
        }
    )


def _detect_provider() -> str:
    explicit = os.getenv("LLM_INSPECTOR_PROVIDER", "").lower()
    if explicit:
        return explicit
    if os.getenv("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.getenv("OPENAI_API_KEY"):
        return "openai"
    if os.getenv("GROQ_API_KEY"):
        return "groq"
    if os.getenv("GEMINI_API_KEY"):
        return "gemini"
    if os.getenv("OLLAMA_BASE_URL") or os.getenv("LLM_INSPECTOR_PROVIDER", "").lower() == "ollama":
        return "ollama"
    return "anthropic"


def _detect_api_key(provider: str) -> str | None:
    env_map = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "groq": "GROQ_API_KEY",
        "gemini": "GEMINI_API_KEY",
    }
    return os.getenv(env_map.get(provider, ""))


def _detect_model(provider: str) -> str:
    explicit = os.getenv("LLM_INSPECTOR_MODEL")
    if explicit:
        return explicit
    from llm_inspector.agent.llm_client import DEFAULT_MODELS
    return DEFAULT_MODELS.get(provider, "gpt-4o")


@dataclass
class Settings:
    provider: str = ""
    api_key: str | None = None
    model: str = ""
    base_url: str | None = os.getenv("LLM_INSPECTOR_BASE_URL") or os.getenv("OLLAMA_BASE_URL")
    data_dir: Path = Path(os.getenv("LLM_INSPECTOR_DATA_DIR", ".llm_inspector_data"))
    budget: Budget = field(default_factory=Budget)

    def __post_init__(self) -> None:
        if not self.provider:
            self.provider = _detect_provider()
        if not self.api_key:
            self.api_key = _detect_api_key(self.provider)
        if not self.model:
            self.model = _detect_model(self.provider)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "reports").mkdir(parents=True, exist_ok=True)
        (self.data_dir / "scans").mkdir(parents=True, exist_ok=True)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "llm_inspector.db"


def get_settings(
    api_key_override: str | None = None,
    provider_override: str | None = None,
    model_override: str | None = None,
    base_url_override: str | None = None,
) -> Settings:
    settings = Settings()
    if provider_override:
        settings.provider = provider_override.lower()
        if not api_key_override:
            settings.api_key = _detect_api_key(settings.provider)
        settings.model = _detect_model(settings.provider)
    if api_key_override:
        settings.api_key = api_key_override
    if model_override:
        settings.model = model_override
    if base_url_override:
        settings.base_url = base_url_override
    return settings
