"""Acceptance tests for cache hits, offline mode, and validated responses."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import BaseModel

from securelens.config import Settings
from securelens.llm import LLMClient, LLMError


class Answer(BaseModel):
    ok: bool
    reason: str


class FakeResponses:
    def __init__(self):
        self.calls = 0

    def create(self, **kwargs):
        self.calls += 1
        return SimpleNamespace(output_text=json.dumps({"ok": True, "reason": "validated"}), status="completed", output=[])


class FakeOpenAI:
    def __init__(self):
        self.responses = FakeResponses()


def settings(cache_dir: Path, offline: bool = False) -> Settings:
    return Settings("test-key-never-cached", "test-model", offline, 0.7, None, 10, cache_dir)


def test_same_operation_uses_cache_without_second_api_request(tmp_path):
    api = FakeOpenAI()
    llm = LLMClient(settings(tmp_path), client=api)

    first = llm.complete("triage", "system", "input", Answer)
    second = llm.complete("triage", "system", "input", Answer)

    assert first == second
    assert api.responses.calls == 1
    assert llm.stats.api_calls == 1
    assert llm.stats.misses == 1
    assert llm.stats.hits == 1
    cache_text = next(tmp_path.glob("*.json")).read_text(encoding="utf-8")
    assert "test-key-never-cached" not in cache_text


def test_offline_mode_uses_cached_response(tmp_path):
    api = FakeOpenAI()
    LLMClient(settings(tmp_path), client=api).complete("triage", "system", "input", Answer)
    offline = LLMClient(settings(tmp_path, offline=True), client=api)

    assert offline.complete("triage", "system", "input", Answer).ok is True
    assert offline.stats.hits == 1
    assert api.responses.calls == 1


def test_offline_cache_miss_is_actionable_and_makes_no_request(tmp_path):
    api = FakeOpenAI()
    llm = LLMClient(settings(tmp_path, offline=True), client=api)

    with pytest.raises(LLMError, match="Offline mode.*no valid cached triage response"):
        llm.complete("triage", "system", "uncached input", Answer)

    assert api.responses.calls == 0
    assert llm.stats.api_calls == 0
