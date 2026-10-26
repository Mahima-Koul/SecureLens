"""Acceptance tests for cache hits, offline mode, and validated responses."""

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import BaseModel

from securelens.config import Settings
from securelens.llm import LLMClient, LLMError


class Answer(BaseModel):
    ok: bool
    reason: str


class FakeInteractions:
    def __init__(self):
        self.calls = 0

    def create(self, **kwargs):
        self.last_request = kwargs
        self.calls += 1
        return SimpleNamespace(output_text=json.dumps({"ok": True, "reason": "validated"}), status="completed", output=[])


class FakeGemini:
    def __init__(self):
        self.interactions = FakeInteractions()


def settings(cache_dir: Path, offline: bool = False) -> Settings:
    return Settings("test-key-never-cached", "test-model", offline, 0.7, None, 10, cache_dir)


def test_same_operation_uses_cache_without_second_api_request(tmp_path):
    api = FakeGemini()
    llm = LLMClient(settings(tmp_path), client=api)

    first = llm.complete("triage", "system", "input", Answer)
    second = llm.complete("triage", "system", "input", Answer)

    assert first == second
    assert api.interactions.calls == 1
    assert api.interactions.last_request["response_format"]["mime_type"] == "application/json"
    assert api.interactions.last_request["model"] == "test-model"
    assert api.interactions.last_request["system_instruction"] == "system"
    assert api.interactions.last_request["input"] == "input"
    assert llm.stats.api_calls == 1
    assert llm.stats.misses == 1
    assert llm.stats.hits == 1
    cache_text = next(tmp_path.glob("*.json")).read_text(encoding="utf-8")
    assert "test-key-never-cached" not in cache_text


def test_offline_mode_uses_cached_response(tmp_path):
    api = FakeGemini()
    LLMClient(settings(tmp_path), client=api).complete("triage", "system", "input", Answer)
    offline = LLMClient(settings(tmp_path, offline=True), client=api)

    assert offline.complete("triage", "system", "input", Answer).ok is True
    assert offline.stats.hits == 1
    assert api.interactions.calls == 1


def test_offline_cache_miss_is_actionable_and_makes_no_request(tmp_path):
    api = FakeGemini()
    llm = LLMClient(settings(tmp_path, offline=True), client=api)

    with pytest.raises(LLMError, match="Offline mode.*no valid cached triage response"):
        llm.complete("triage", "system", "uncached input", Answer)

    assert api.interactions.calls == 0
    assert llm.stats.api_calls == 0


def test_gemini_client_is_initialized_with_key_and_timeout(tmp_path, monkeypatch):
    from google import genai

    fake = FakeGemini()
    captured = {}

    def make_client(**kwargs):
        captured.update(kwargs)
        return fake

    monkeypatch.setattr(genai, "Client", make_client)
    llm = LLMClient(settings(tmp_path))

    assert llm.complete("triage", "system", "input", Answer).ok
    assert captured["api_key"] == "test-key-never-cached"
    assert captured["http_options"]["timeout"] == 10_000


def test_missing_gemini_key_has_actionable_error(tmp_path):
    llm = LLMClient(replace(settings(tmp_path), gemini_api_key=None))

    with pytest.raises(LLMError, match="GEMINI_API_KEY is required"):
        llm.complete("triage", "system", "input", Answer)
