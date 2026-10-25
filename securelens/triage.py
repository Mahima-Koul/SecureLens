"""Conservative LLM triage for static-analysis findings."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from .config import load_settings
from .context import Context
from .llm import LLMClient, LLMError
from .models import Finding, Verdict
from .prompts import TRIAGE_SYSTEM_PROMPT


class TriageResponse(BaseModel):
    """Validated model response for one finding."""

    is_true_positive: bool
    confidence: float = Field(ge=0, le=1)
    reason: str = Field(min_length=1)


def triage(
    finding: Finding,
    context: Context,
    *,
    llm_client: LLMClient | None = None,
    threshold: float | None = None,
) -> Verdict:
    """Assess one finding, conservatively confirming uncertain or failed calls."""
    client = llm_client or LLMClient()
    evidence = {
        "finding": finding.model_dump(mode="json"),
        "complete_enclosing_function_or_nearby_source": context.source,
        "imports": context.imports,
        "numbered_lines": context.numbered_lines,
    }
    try:
        response = client.complete(
            "triage", TRIAGE_SYSTEM_PROMPT,
            json.dumps(evidence, sort_keys=True, ensure_ascii=False), TriageResponse,
        )
        return Verdict(
            finding_id=finding.id,
            is_true_positive=response.is_true_positive,
            confidence=response.confidence,
            reason=_one_sentence(response.reason),
        )
    except Exception as exc:
        # Do not pass through arbitrary provider text, which can include request data.
        detail = "offline cache entry is missing" if isinstance(exc, LLMError) and "Offline mode" in str(exc) else type(exc).__name__
        return Verdict(
            finding_id=finding.id,
            is_true_positive=True,
            confidence=0.0,
            reason=f"Triage was unresolved ({detail}); the finding is conservatively confirmed.",
        )


def is_confirmed(verdict: Verdict, threshold: float | None = None) -> bool:
    """Return whether a finding should remain in the confirmed set."""
    if verdict.is_true_positive:
        return True
    cutoff = load_settings().triage_threshold if threshold is None else threshold
    return verdict.confidence < cutoff


def _one_sentence(reason: str) -> str:
    """Normalize a response reason to one concise sentence."""
    cleaned = " ".join(reason.split())
    if not cleaned:
        return "The evidence was insufficient to assess this finding."
    for marker in (". ", "! ", "? "):
        if marker in cleaned:
            cleaned = cleaned.split(marker, 1)[0] + marker[0]
            break
    if cleaned[-1] not in ".!?":
        cleaned += "."
    return cleaned
