"""Tests for scanner normalization and Python context extraction."""

from securelens.context import extract_context
from securelens.models import Finding
from securelens.scanner import _excludes, _normalize_bandit, _normalize_semgrep, _deduplicate


def finding(line=3):
    return Finding(id="id", tool="bandit", rule_id="B608", file="app.py", line=line,
                   severity="MEDIUM", message="Possible SQL injection", snippet="query = f'{name}'",
                   fingerprint="fp")


def test_context_returns_enclosing_function_imports_and_numbered_source(tmp_path):
    (tmp_path / "app.py").write_text("import os\n\ndef lookup(name):\n    query = name\n    return query\n", encoding="utf-8")
    item = finding(4)
    context = extract_context(item, tmp_path)

    assert context.function_name == "lookup"
    assert context.source.startswith("def lookup")
    assert context.imports == ["import os"]
    assert "   4:     query = name" in context.numbered_lines
    assert item.function_name == "lookup"


def test_context_rejects_path_escape(tmp_path):
    item = finding()
    item.file = "../outside.py"
    try:
        extract_context(item, tmp_path)
    except ValueError as exc:
        assert "escapes" in str(exc)
    else:
        raise AssertionError("path traversal was accepted")


def test_semgrep_and_bandit_alerts_normalize_to_findings(tmp_path):
    semgrep = {"results": [{"path": "app.py", "check_id": "python.sql", "start": {"line": 2},
                "extra": {"severity": "ERROR", "message": "SQL query injection", "lines": "execute(query)"}}]}
    bandit = {"results": [{"filename": str(tmp_path / "app.py"), "test_id": "B608", "line_number": 2,
                "issue_severity": "MEDIUM", "issue_text": "Possible SQL injection", "code": "execute(query)"}]}
    assert _normalize_semgrep(semgrep, tmp_path)[0].severity == "HIGH"
    assert _normalize_bandit(bandit, tmp_path)[0].file == "app.py"
    combined = _deduplicate(_normalize_semgrep(semgrep, tmp_path) + _normalize_bandit(bandit, tmp_path))
    assert len(combined) == 1
    assert "overlapping" in combined[0].message


def test_findings_outside_project_are_discarded(tmp_path):
    external = tmp_path.parent / "outside.py"
    data = {"results": [{"filename": str(external), "test_id": "B603", "line_number": 1,
                         "issue_severity": "HIGH", "issue_text": "issue", "code": "run()"}]}
    assert _normalize_bandit(data, tmp_path) == []


def test_deduplication_preserves_same_tool_rules():
    first = finding()
    second = finding()
    second.id = "another"
    second.rule_id = "B607"
    assert len(_deduplicate([first, second])) == 2


def test_scanner_excludes_do_not_hide_a_patched_project_root():
    from pathlib import Path
    excludes = _excludes(Path("workdir/run1/sample_patched").resolve())
    assert "workdir" not in excludes
    assert "*_patched" not in excludes


def test_semgrep_snippet_uses_target_source_not_untrusted_metadata(tmp_path):
    (tmp_path / "app.py").write_text("def run():\n    dangerous(value)\n", encoding="utf-8")
    data = {"results": [{"path": "app.py", "check_id": "python.danger", "start": {"line": 2},
                         "end": {"line": 2}, "extra": {"severity": "WARNING", "message": "alert",
                                                               "lines": "requires login"}}]}

    finding = _normalize_semgrep(data, tmp_path)[0]

    assert finding.snippet == "    dangerous(value)"
