"""Deterministic triage acceptance tests using validated mock responses."""

from pathlib import Path

from securelens.context import extract_context
from securelens.models import Finding
from securelens.triage import TriageResponse, is_confirmed, triage


class MockLLM:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.operations = []

    def complete(self, operation, system_prompt, user_input, response_model):
        self.operations.append((operation, system_prompt, user_input, response_model))
        if self.error:
            raise self.error
        return self.response


def make_finding(file, line, rule, severity="HIGH"):
    return Finding(id=f"{file}-{line}", tool="bandit", rule_id=rule, file=file, line=line,
                   severity=severity, message="scanner alert", snippet="source", fingerprint="fp")


def test_sqli_is_confirmed_and_parameterized_trap_is_dismissed(tmp_path):
    (tmp_path / "app.py").write_text(
        "import sqlite3\n\ndef unsafe(name):\n    return db.execute(f\"SELECT * FROM users WHERE name='{name}'\")\n"
        "\ndef safe(name):\n    return db.execute('SELECT * FROM users WHERE name=?', (name,))\n",
        encoding="utf-8",
    )
    injection = make_finding("app.py", 4, "B608")
    safe_query = make_finding("app.py", 7, "B608")
    injection_context = extract_context(injection, tmp_path)
    safe_context = extract_context(safe_query, tmp_path)

    confirmed = triage(injection, injection_context,
                       llm_client=MockLLM(TriageResponse(is_true_positive=True, confidence=.96,
                                                          reason="User input is interpolated into SQL.")))
    dismissed = triage(safe_query, safe_context,
                       llm_client=MockLLM(TriageResponse(is_true_positive=False, confidence=.94,
                                                          reason="The value is bound as a query parameter.")))

    assert is_confirmed(confirmed, .7)
    assert not is_confirmed(dismissed, .7)
    assert confirmed.finding_id == injection.id


def test_uncertain_false_positive_is_confirmed():
    finding = make_finding("app.py", 10, "B608")
    verdict = triage(finding, extract_context(finding, Path("samples/sqli_app")),
                     llm_client=MockLLM(TriageResponse(is_true_positive=False, confidence=.4,
                                                        reason="This might be harmless.")))
    assert is_confirmed(verdict, .7)


def test_triage_failure_is_unresolved_and_conservatively_confirmed():
    finding = make_finding("app.py", 10, "B608")
    context = extract_context(finding, Path("samples/sqli_app"))
    verdict = triage(finding, context, llm_client=MockLLM(error=RuntimeError("private request content")))
    assert verdict.is_true_positive is True
    assert verdict.confidence == 0
    assert "RuntimeError" in verdict.reason
    assert "private request content" not in verdict.reason
    assert is_confirmed(verdict)


def test_high_severity_false_positive_below_threshold_stays_confirmed():
    verdict = triage(make_finding("app.py", 1, "B999", "HIGH"),
                     extract_context(make_finding("app.py", 1, "B999"), Path("samples/sqli_app")),
                     llm_client=MockLLM(TriageResponse(is_true_positive=False, confidence=.69,
                                                        reason="The evidence is incomplete.")))
    assert is_confirmed(verdict, .7)
