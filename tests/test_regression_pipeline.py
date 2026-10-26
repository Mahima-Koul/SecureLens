"""Tests for pytest isolation, regression identities, and final report statuses."""

import tempfile
import json
from pathlib import Path

from securelens import pipeline
from securelens.fixer import PatchResponse
from securelens.models import DiffResult, Finding, PipelineReport, RegressionResult, TestResult as SecureTestResult
from securelens.regression import compare_tests, run_tests
from securelens.report import finalize_report, render_summary
from securelens.triage import TriageResponse


def test_test_identity_comparison_ignores_preexisting_failures():
    original = SecureTestResult(failed=1, failed_tests=["test_app::test_old_failure"])
    patched = SecureTestResult(failed=2, failed_tests=["test_app::test_old_failure", "test_app::test_new_failure"])

    result = compare_tests(original, patched)

    assert result.newly_failing == ["test_app::test_new_failure"]
    assert result.fixed_tests == []


def test_compare_tests_identifies_fixed_and_newly_failing_tests():
    original = SecureTestResult(failed=1, failed_tests=["test_app::test_sqli_remediated"])
    patched = SecureTestResult(failed=1, failed_tests=["test_app::test_unrelated_broken"])

    result = compare_tests(original, patched)

    assert result.fixed_tests == ["test_app::test_sqli_remediated"]
    assert result.newly_failing == ["test_app::test_unrelated_broken"]


def test_run_tests_parses_junit_and_records_new_failures(tmp_path, monkeypatch):
    junit_temp = tmp_path / "junit-temp"
    junit_temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(junit_temp))
    original = tmp_path / "original"
    patched = tmp_path / "patched"
    for project in (original, patched):
        (project / "tests").mkdir(parents=True)
    (original / "tests" / "test_app.py").write_text(
        "def test_old_failure():\n    assert False\n\ndef test_passes():\n    assert True\n", encoding="utf-8")
    (patched / "tests" / "test_app.py").write_text(
        "def test_old_failure():\n    assert False\n\ndef test_new_failure():\n    assert False\n\ndef test_passes():\n    assert True\n", encoding="utf-8")

    baseline = run_tests(original, timeout=20)
    after = run_tests(patched, timeout=20)
    result = compare_tests(baseline, after)

    assert baseline.failed == 1 and baseline.passed == 1
    assert after.failed == 2 and after.passed == 1
    assert result.newly_failing == ["tests.test_app::test_new_failure"]


def make_finding():
    return Finding(id="x", tool="bandit", rule_id="B307", file="app.py", line=1,
                   severity="MEDIUM", message="eval", snippet="eval(x)", fingerprint="fp")


def test_report_is_safe_only_when_required_evidence_is_complete():
    complete = PipelineReport(
        project="demo", diff=DiffResult(fixed=[make_finding()], remaining=[], new=[]),
        regression=RegressionResult(original=SecureTestResult(passed=2), patched=SecureTestResult(passed=2)),
    )
    assert finalize_report(complete).final_status == "SAFE"
    assert "No new findings" in render_summary(complete)

    incomplete = finalize_report(PipelineReport(project="demo", errors=["scanner unavailable"]))
    assert incomplete.final_status == "INCOMPLETE"


def test_report_is_risky_for_new_findings_or_regressions():
    new_finding = make_finding()
    report = PipelineReport(project="demo", diff=DiffResult(fixed=[], remaining=[], new=[new_finding]),
                            regression=RegressionResult(original=SecureTestResult(passed=1),
                                                        patched=SecureTestResult(failed=1),
                                                        newly_failing=["test_new"]))

    assert finalize_report(report).final_status == "RISKY"


def test_baseline_test_error_is_not_misreported_as_pass(tmp_path, monkeypatch):
    junit_temp = tmp_path / "junit-temp"
    junit_temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(junit_temp))
    result = run_tests(tmp_path / "missing", timeout=1)
    assert result.errors == 1
    assert "does not exist" in result.raw_output_tail


class WowMockLLM:
    """Return a deliberately naive literal_eval patch to exercise the WOW regression."""

    def complete(self, operation, system_prompt, user_input, response_model):
        if operation == "triage":
            return TriageResponse(is_true_positive=True, confidence=.99,
                                  reason="The expression reaches eval from caller-controlled input.")
        evidence = json.loads(user_input)
        replacement = evidence["complete_original_file"].replace(
            'return eval(expression, {"__builtins__": {}}, {})',
            "return ast.literal_eval(expression)",
        )
        return PatchResponse(patched_code=replacement,
                             explanation="Use literal evaluation to avoid arbitrary code execution.")


def test_wow_pipeline_demonstrates_a_newly_failing_test(tmp_path, monkeypatch):
    sample = Path("samples/wow_app").resolve()
    junit_temp = tmp_path / "junit-temp"
    junit_temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(junit_temp))
    finding = Finding(id="wow-eval", tool="bandit", rule_id="B307", file="app.py", line=20,
                      severity="MEDIUM", message="eval input", snippet="eval(expression)",
                      function_name="calculate", fingerprint="fp")
    monkeypatch.setattr(pipeline, "scan_stage", lambda _root: ([finding.model_copy(deep=True)], []))
    monkeypatch.setattr(pipeline, "diff_stage", lambda before, _patched, **_kwargs:
                        (DiffResult(fixed=[before[0]], remaining=[], new=[]), []))
    original_code = (sample / "app.py").read_text(encoding="utf-8")

    report = pipeline.run_pipeline(sample, llm_client=WowMockLLM(), workdir=tmp_path / "workdir", timeout=20)

    assert report.final_status == "RISKY"
    assert report.regression is not None
    assert "tests.test_app::test_calculate_preserves_precedence" in report.regression.newly_failing
    assert (sample / "app.py").read_text(encoding="utf-8") == original_code
