"""Fingerprint and classify findings before and after a patch."""

from __future__ import annotations

import hashlib
import re
from collections import Counter

from .models import DiffResult, Finding

_STRING_LITERAL = re.compile(r"(?:'''(?:\\.|[^\\])*?'''|\"\"\"(?:\\.|[^\\])*?\"\"\"|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")", re.DOTALL)
_NUMBER_LITERAL = re.compile(r"(?<![\w.])(?:0[xX][\da-fA-F]+|(?:\d+\.\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?)(?![\w.])")


def normalized_snippet(snippet: str) -> str:
    """Collapse whitespace and mask string and numeric literals."""
    masked = _STRING_LITERAL.sub("<STR>", snippet)
    masked = _NUMBER_LITERAL.sub("<NUM>", masked)
    return re.sub(r"\s+", " ", masked).strip()


def fingerprint(finding: Finding) -> str:
    """Return a line-independent SHA-1 fingerprint for one finding."""
    material = f"{finding.rule_id}{finding.function_name or ''}{normalized_snippet(finding.snippet)}"
    return hashlib.sha1(material.encode("utf-8")).hexdigest()


def classify(before: list[Finding], after: list[Finding]) -> DiffResult:
    """Classify fixed, remaining, and new findings using multiset matching."""
    remaining_after = Counter(fingerprint(item) for item in after)
    fixed: list[Finding] = []
    remaining: list[Finding] = []
    for item in before:
        key = fingerprint(item)
        if remaining_after[key] > 0:
            remaining_after[key] -= 1
        else:
            fixed.append(item)
    before_counts = Counter(fingerprint(item) for item in before)
    # A matched result should show current line numbers and current source evidence.
    for item in after:
        key = fingerprint(item)
        if before_counts[key] > 0:
            remaining.append(item)
            before_counts[key] -= 1
    new: list[Finding] = []
    matched_counts = Counter(fingerprint(item) for item in remaining)
    for item in after:
        key = fingerprint(item)
        if matched_counts[key] > 0:
            matched_counts[key] -= 1
        else:
            new.append(item)
    return DiffResult(fixed=fixed, remaining=remaining, new=new)
