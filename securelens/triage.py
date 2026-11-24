"""Conservative, evidence-grounded LLM triage for static-analysis findings."""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, Field

from .config import load_settings
from .context import Context
from .llm import LLMClient, LLMError
from .models import Finding, Verdict
from .prompts import TRIAGE_SYSTEM_PROMPT


class TriageResponse(BaseModel):
    """Validated model response for one finding, with optional evidence grounding."""

    is_true_positive: bool
    confidence: float = Field(ge=0, le=1)
    reason: str = Field(min_length=1)
    evidence_line: int | None = None
    evidence_snippet: str | None = None


def verify_evidence_grounding(
    finding: Finding,
    context: Context,
    evidence_line: int | None,
    evidence_snippet: str | None,
) -> tuple[bool, int, str]:
    """Verify that model-cited line and code evidence correspond to the actual source context."""
    default_line = finding.line
    default_snippet = (finding.snippet.splitlines()[0].strip() if finding.snippet.strip() else "")

    numbered_map: dict[int, str] = {}
    for raw_line in context.numbered_lines.splitlines():
        if ":" in raw_line:
            prefix, content = raw_line.split(":", 1)
            if prefix.strip().isdigit():
                numbered_map[int(prefix.strip())] = content.strip()

    grounded = True
    resolved_line = evidence_line if evidence_line is not None else default_line
    resolved_snippet = (evidence_snippet or "").strip() or default_snippet

    if evidence_line is not None and numbered_map and evidence_line not in numbered_map:
        grounded = False
    if evidence_snippet and evidence_snippet.strip():
        needle = " ".join(evidence_snippet.split())
        haystack = " ".join(f"{context.source}\n{context.numbered_lines}\n{finding.snippet}".split())
        if needle and needle not in haystack:
            grounded = False

    if grounded and resolved_line in numbered_map and not resolved_snippet:
        resolved_snippet = numbered_map[resolved_line]

    return grounded, resolved_line, resolved_snippet


def _classify_status(
    is_true_positive: bool,
    confidence: float,
    threshold: float,
    grounding_verified: bool,
) -> Literal["confirmed", "dismissed", "uncertain"]:
    """Determine 3-way triage status (Confirmed / Dismissed / Uncertain)."""
    if not grounding_verified:
        return "uncertain"
    if confidence < threshold:
        return "uncertain"
    return "confirmed" if is_true_positive else "dismissed"


def triage(
    finding: Finding,
    context: Context,
    *,
    llm_client: LLMClient | None = None,
    threshold: float | None = None,
) -> Verdict:
    """Assess one finding, verifying evidence grounding and conservatively confirming uncertain or failed calls."""
    client = llm_client or LLMClient()
    cutoff = load_settings().triage_threshold if threshold is None else threshold
    evidence = {
        "finding": finding.model_dump(mode="json"),
        "complete_enclosing_function_or_nearby_source": context.source,
        "imports": context.imports,
        "numbered_lines": context.numbered_lines,
    }
    try:
        response = client.complete(
            "triage",
            TRIAGE_SYSTEM_PROMPT,
            json.dumps(evidence, sort_keys=True, ensure_ascii=False),
            TriageResponse,
        )
        grounded, ev_line, ev_snippet = verify_evidence_grounding(
            finding, context, response.evidence_line, response.evidence_snippet
        )
        status = _classify_status(response.is_true_positive, response.confidence, cutoff, grounded)
        reason = _one_sentence(response.reason)
        if not grounded and not response.is_true_positive:
            reason = f"{reason} (Evidence grounding could not be verified; retained conservatively as uncertain.)"
        return Verdict(
            finding_id=finding.id,
            is_true_positive=response.is_true_positive if grounded else True,
            status=status,
            confidence=response.confidence,
            reason=reason,
            evidence_line=ev_line,
            evidence_snippet=ev_snippet,
            grounding_verified=grounded,
        )
    except Exception as exc:
        # Do not pass through arbitrary provider text, which can include request data.
        detail = (
            "offline cache entry is missing"
            if isinstance(exc, LLMError) and "Offline mode" in str(exc)
            else type(exc).__name__
        )
        return Verdict(
            finding_id=finding.id,
            is_true_positive=True,
            status="uncertain",
            confidence=0.0,
            reason=f"Triage was unresolved ({detail}); the finding is conservatively confirmed.",
            evidence_line=finding.line,
            evidence_snippet=(finding.snippet.splitlines()[0].strip() if finding.snippet.strip() else ""),
            grounding_verified=False,
        )


def is_confirmed(verdict: Verdict, threshold: float | None = None) -> bool:
    """Return whether a finding should remain in the confirmed/active remediation set."""
    if not verdict.grounding_verified:
        return True
    if verdict.status == "uncertain":
        return True
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
