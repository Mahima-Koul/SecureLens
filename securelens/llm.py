"""Gemini API access with validated, atomic disk caching."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from .config import Settings, load_settings

T = TypeVar("T", bound=BaseModel)
CACHE_VERSION = 1


class LLMError(RuntimeError):
    """Actionable error from configuration, API access, or response validation."""


@dataclass
class CacheStats:
    """Counters for cache behavior and actual network requests."""

    hits: int = 0
    misses: int = 0
    api_calls: int = 0


class LLMClient:
    """Call Gemini with structured output, validated cache, and offline support."""

    def __init__(self, settings: Settings | None = None, *, client: Any = None) -> None:
        self.settings = settings or load_settings()
        self.client = client
        self.stats = CacheStats()

    def complete(self, operation: str, system_prompt: str, user_input: str, response_model: type[T]) -> T:
        """Return a validated response, using a matching cache entry when available."""
        schema = response_model.model_json_schema()
        material = json.dumps({
            "version": CACHE_VERSION, "model": self.settings.gemini_model,
            "operation": operation, "system": system_prompt, "input": user_input, "schema": schema,
        }, sort_keys=True, ensure_ascii=False)
        key = hashlib.sha256(material.encode("utf-8")).hexdigest()
        cache_path = self.settings.cache_dir / f"{key}.json"
        if cache_path.exists():
            try:
                record = json.loads(cache_path.read_text(encoding="utf-8"))
                if record.get("version") == CACHE_VERSION and record.get("key") == key:
                    result = response_model.model_validate(record["result"])
                    self.stats.hits += 1
                    return result
            except (OSError, ValueError, KeyError, ValidationError, TypeError):
                pass
        self.stats.misses += 1
        if self.settings.offline:
            raise LLMError(f"Offline mode: no valid cached {operation} response. Run online once to populate {cache_path}.")
        if self.client is None:
            if not self.settings.gemini_api_key:
                raise LLMError("GEMINI_API_KEY is required for live calls. Set it in your environment or .env file.")
            try:
                from google import genai
                self.client = genai.Client(
                    api_key=self.settings.gemini_api_key,
                    http_options={"timeout": self.settings.tool_timeout * 1000},
                )
            except Exception as exc:
                raise LLMError(f"Could not initialize the Gemini client: {type(exc).__name__}.") from exc

        errors: list[str] = []
        for attempt in range(2):
            self.stats.api_calls += 1
            try:
                response = self.client.interactions.create(
                    model=self.settings.gemini_model,
                    system_instruction=system_prompt,
                    input=user_input,
                    response_format={
                        "type": "text", "mime_type": "application/json", "schema": schema,
                    },
                    timeout=self.settings.tool_timeout,
                )
                if getattr(response, "status", None) == "incomplete":
                    raise LLMError("Gemini returned an incomplete response.")
                if self._has_refusal(response):
                    raise LLMError("Gemini refused the request; no response was cached.")
                result = response_model.model_validate_json(response.output_text)
                self._write_cache(cache_path, key, result.model_dump(mode="json"))
                return result
            except ValidationError as exc:
                errors.append(f"invalid structured output: {exc}")
            except LLMError:
                raise
            except Exception as exc:
                # Do not include provider exception text: it can contain request details.
                name = type(exc).__name__
                errors.append(f"Gemini request failed ({name}).")
                if getattr(exc, "code", None) in {401, 403}:
                    raise LLMError("Gemini authentication or permission failed. Check the API key and model access.") from exc
                if attempt == 1:
                    raise LLMError(errors[-1]) from exc
        raise LLMError("Could not validate Gemini response after one retry: " + "; ".join(errors))

    @staticmethod
    def _has_refusal(response: Any) -> bool:
        """Detect provider refusal blocks in response output items or steps."""
        items = list(getattr(response, "output", []) or [])
        items.extend(getattr(response, "steps", []) or [])
        for item in items:
            for content in getattr(item, "content", []) or []:
                if getattr(content, "type", None) == "refusal":
                    return True
            if getattr(item, "type", None) == "refusal":
                return True
        return False

    @staticmethod
    def _write_cache(path: Path, key: str, result: dict[str, Any]) -> None:
        """Write a validated response atomically without storing credentials."""
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=f".{key}.", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"version": CACHE_VERSION, "key": key, "result": result}, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
