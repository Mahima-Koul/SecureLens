"""Unit and integration tests for the 9-stage SecureLens Java/Semgrep* & Repository upgrade."""

from __future__ import annotations

from pathlib import Path

import pytest

from securelens.context import extract_context
from securelens.fixer import PatchResponse, apply_patches, generate_patch
from securelens.models import DiffResult, Finding, PipelineReport, RegressionResult, TestResult as SecureTestResult
from securelens.repo_manager import list_repo_files, read_repo_file, validate_github_url
from securelens.report import finalize_report
from securelens.scanner import _normalize_semgrep, _resolve_semgrep_config
from securelens.triage import TriageResponse, is_confirmed, triage


class MockLLM:
    def __init__(self, response):
        self.response = response

    def complete(self, *args, **kwargs):
        return self.response


def test_validate_github_url_accepts_valid_and_rejects_unsafe():
    url, owner, repo = validate_github_url("https://github.com/apache/camel")
    assert url == "https://github.com/apache/camel.git"
    assert owner == "apache"
    assert repo == "camel"

    with pytest.raises(ValueError):
        validate_github_url("http://github.com/apache/camel")
    with pytest.raises(ValueError):
        validate_github_url("https://evil.com/apache/camel")
    with pytest.raises(ValueError):
        validate_github_url("https://github.com/../etc")


def test_repo_file_explorer_lists_and_reads_java_safely(tmp_path):
    (tmp_path / "src").mkdir()
    java_file = tmp_path / "src" / "Main.java"
    java_file.write_text("package demo;\npublic class Main {}\n", encoding="utf-8")

    # Benchmark/test metadata and marker files should be hidden in the UI file explorer
    (tmp_path / "ground_truth.json").write_text("{}", encoding="utf-8")
    (tmp_path / ".securelens-patched").write_text("1", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("def test_ok(): pass\n", encoding="utf-8")

    files = list_repo_files(tmp_path)
    assert files == ["src/Main.java"]
    assert "public class Main" in read_repo_file(tmp_path, "src/Main.java")

    with pytest.raises(ValueError):
        read_repo_file(tmp_path, "../outside.java")


def test_semgrep_star_config_selected_for_java_and_cwe_extracted(tmp_path):
    config_path = _resolve_semgrep_config(None, has_java=True)
    assert "semgrep_yaml_files" in config_path

    (tmp_path / "App.java").write_text(
        "public class App {\n    public void run(String cmd) throws Exception {\n        Runtime.getRuntime().exec(cmd);\n    }\n}\n",
        encoding="utf-8",
    )
    raw = {
        "results": [
            {
                "path": "App.java",
                "check_id": "semgreph_data.semgrep_yaml_files.command-injection-formatted-runtime-call-copy",
                "start": {"line": 3},
                "end": {"line": 3},
                "extra": {
                    "severity": "ERROR",
                    "message": "Command injection",
                    "metadata": {"cwe": ["CWE-78: OS Command Injection"]},
                },
            }
        ]
    }
    findings = _normalize_semgrep(raw, tmp_path)
    assert len(findings) == 1
    assert findings[0].file == "App.java"
    assert findings[0].rule_id == "command-injection-formatted-runtime-call-copy"
    assert findings[0].cwe == "CWE-78: OS Command Injection"


def test_java_context_extraction_finds_imports_and_enclosing_method(tmp_path):
    java_code = (
        "package sample.cmdi;\n\n"
        "import java.io.IOException;\n"
        "import java.util.Random;\n\n"
        "public class App {\n"
        "    public Process pingHostUnsafe(String host) throws IOException {\n"
        "        Runtime rt = Runtime.getRuntime();\n"
        "        return rt.exec(\"ping -c 1 \" + host);\n"
        "    }\n"
        "}\n"
    )
    (tmp_path / "App.java").write_text(java_code, encoding="utf-8")
    finding = Finding(
        id="j1",
        tool="semgrep",
        rule_id="command-injection-formatted-runtime-call-copy",
        file="App.java",
        line=9,
        severity="HIGH",
        message="Command injection",
        snippet='return rt.exec("ping -c 1 " + host);',
        cwe="CWE-78",
        fingerprint="fp",
    )
    ctx = extract_context(finding, tmp_path)
    assert ctx.function_name == "pingHostUnsafe"
    assert finding.function_name == "pingHostUnsafe"
    assert "public Process pingHostUnsafe" in ctx.source
    assert "import java.io.IOException;" in ctx.imports


def test_evidence_grounding_downgrades_unverified_dismissal_to_uncertain(tmp_path):
    (tmp_path / "App.java").write_text(
        "public class App {\n    public void run(String x) {\n        exec(x);\n    }\n}\n",
        encoding="utf-8",
    )
    finding = Finding(
        id="j2",
        tool="semgrep",
        rule_id="cmd-rule",
        file="App.java",
        line=3,
        severity="HIGH",
        message="Command injection",
        snippet="exec(x);",
        fingerprint="fp",
    )
    ctx = extract_context(finding, tmp_path)

    # AI tries to dismiss by citing a non-existent line 999 and hallucinated sanitizer
    ungrounded_verdict = triage(
        finding,
        ctx,
        llm_client=MockLLM(
            TriageResponse(
                is_true_positive=False,
                confidence=0.95,
                reason="Input is sanitized on line 999.",
                evidence_line=999,
                evidence_snippet="sanitize(x);",
            )
        ),
    )
    assert ungrounded_verdict.grounding_verified is False
    assert ungrounded_verdict.status == "uncertain"
    assert is_confirmed(ungrounded_verdict, 0.7) is True


def test_java_patch_generation_and_isolated_application(tmp_path):
    project = tmp_path / "java_proj"
    project.mkdir()
    java_file = project / "App.java"
    orig = "public class App {\n    void bad() {}\n}\n"
    fixed = "public class App {\n    void safe() {}\n}\n"
    java_file.write_text(orig, encoding="utf-8")

    finding = Finding(
        id="j3",
        tool="semgrep",
        rule_id="rule",
        file="App.java",
        line=2,
        severity="HIGH",
        message="msg",
        snippet="void bad() {}",
        fingerprint="fp",
    )
    patch = generate_patch(
        java_file,
        [finding],
        project_dir=project,
        llm_client=MockLLM(PatchResponse(patched_code=fixed, explanation="Replaced bad with safe.")),
    )
    assert patch.file == "App.java"
    patched_copy = apply_patches(project, [patch], workdir=tmp_path / "workdir")
    assert (patched_copy / "App.java").read_text(encoding="utf-8") == fixed
    assert java_file.read_text(encoding="utf-8") == orig


def test_absence_of_tests_in_imported_repo_is_incomplete_not_safe():
    report = PipelineReport(
        project="imported_java_repo",
        diff=DiffResult(fixed=[], remaining=[], new=[]),
        regression=RegressionResult(
            original=SecureTestResult(status="no_tests"),
            patched=SecureTestResult(status="no_tests"),
        ),
    )
    finalized = finalize_report(report)
    assert finalized.final_status == "INCOMPLETE"
    assert any("absence of tests" in r for r in finalized.status_reasons)


def test_ui_code_viewer_zoom_controls_and_tree():
    from streamlit.testing.v1 import AppTest

    ui_path = Path(__file__).resolve().parents[1] / "ui" / "app.py"
    at = AppTest.from_file(str(ui_path), default_timeout=15).run()
    assert not at.error
    at.button(key="sl_zoom_in").click().run()
    assert at.session_state["sl_code_font_size"] == 16
    at.button(key="sl_zoom_out").click().run()
    assert at.session_state["sl_code_font_size"] == 14
