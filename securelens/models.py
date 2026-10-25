"""Validated data models shared across SecureLens components."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, ConfigDict


class Finding(BaseModel):
    """A normalized static-analysis finding."""

    id: str
    tool: Literal["semgrep", "bandit"]
    rule_id: str
    file: str
    line: int
    severity: Literal["LOW", "MEDIUM", "HIGH"]
    message: str
    snippet: str
    function_name: str | None = None
    fingerprint: str


class Verdict(BaseModel):
    """LLM assessment of whether a finding is a real vulnerability."""

    finding_id: str
    is_true_positive: bool
    confidence: float = Field(ge=0, le=1)
    reason: str


class Patch(BaseModel):
    """A proposed complete-file change."""

    file: str
    original_code: str
    patched_code: str
    diff: str
    explanation: str
    addressed_finding_ids: list[str]


class DiffResult(BaseModel):
    """Classification of findings across a code change."""

    fixed: list[Finding]
    remaining: list[Finding]
    new: list[Finding]


class TestResult(BaseModel):
    """Pytest result summary."""

    passed: int = 0
    failed: int = 0
    errors: int = 0
    failed_tests: list[str] = Field(default_factory=list)
    raw_output_tail: str = ""


class RegressionResult(BaseModel):
    """Original and patched test results with newly failing tests."""

    original: TestResult
    patched: TestResult
    newly_failing: list[str] = Field(default_factory=list)


class PipelineReport(BaseModel):
    """Serializable summary of a SecureLens pipeline run."""

    model_config = ConfigDict(extra="allow")

    project: str
    patched_project: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    verdicts: list[Verdict] = Field(default_factory=list)
    confirmed: list[Finding] = Field(default_factory=list)
    dismissed: list[Finding] = Field(default_factory=list)
    unresolved: list[Finding] = Field(default_factory=list)
    patches: list[Patch] = Field(default_factory=list)
    diff: DiffResult | None = None
    regression: RegressionResult | None = None
    errors: list[str] = Field(default_factory=list)
    timings: dict[str, float] = Field(default_factory=dict)
    llm_stats: dict[str, int] = Field(default_factory=dict)
    final_status: Literal["SAFE", "RISKY", "INCOMPLETE"] = "INCOMPLETE"
    status_reasons: list[str] = Field(default_factory=list)
