"""Environment-backed SecureLens configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    """Runtime settings loaded from environment variables and `.env`."""

    gemini_api_key: str | None
    gemini_model: str
    offline: bool
    triage_threshold: float
    semgrep_config: str | None
    tool_timeout: int
    cache_dir: Path


def load_settings(*, offline: bool | None = None) -> Settings:
    """Load and validate settings, with optional per-invocation offline override."""
    load_dotenv()
    threshold = float(os.getenv("SECURELENS_TRIAGE_THRESHOLD", "0.7"))
    timeout = int(os.getenv("SECURELENS_TOOL_TIMEOUT", "60"))
    if not 0 <= threshold <= 1:
        raise ValueError("SECURELENS_TRIAGE_THRESHOLD must be between 0 and 1")
    if timeout <= 0:
        raise ValueError("SECURELENS_TOOL_TIMEOUT must be a positive number")
    env_offline = os.getenv("SECURELENS_OFFLINE", "0").strip().lower() in {"1", "true", "yes"}
    return Settings(
        gemini_api_key=os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or None,
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite").strip() or "gemini-3.5-flash-lite",
        offline=env_offline if offline is None else offline,
        triage_threshold=threshold,
        semgrep_config=os.getenv("SECURELENS_SEMGREP_CONFIG") or None,
        tool_timeout=timeout,
        cache_dir=Path(os.getenv("SECURELENS_CACHE_DIR", ".cache/llm")),
    )
