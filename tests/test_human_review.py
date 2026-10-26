"""Unit and integration tests for the human-in-the-loop patch review workflow."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from securelens.differ import classify
from securelens.fixer import PatchResponse
from securelens.models import DiffResult, Finding, Patch, PipelineReport, RegressionResult, TestResult as SecureTestResult
from securelens.pipeline import apply_patches_stage, generate_patches_stage
from securelens.report import finalize_report


class MockLLM:
    """Mock LLM for patch generation."""

    def __init__(self, response: PatchResponse | None = None, error: Exception | None = None):
        self.response = response
        self.error = error

    def complete(self, operation, system_prompt, user_input, response_model):
        if self.error:
            raise self.error
        return self.response


def make_finding(file: str, line: int, rule_id: str, snippet: str, finding_id: str) -> Finding:
    return Finding(
        id=finding_id,
        tool="bandit",
        rule_id=rule_id,
        file=file,
        line=line,
        severity="HIGH",
        message="Vulnerability alert",
        snippet=snippet,
        fingerprint=f"fp-{finding_id}",
    )


def test_patch_model_default_status_is_pending():
    patch = Patch(
        file="app.py",
        original_code="orig",
        patched_code="patch",
        diff="---",
        explanation="fix",
        addressed_finding_ids=["f1"],
    )
    assert patch.status == "pending"
    patch.status = "approved"
    assert patch.status == "approved"
    patch.status = "rejected"
    assert patch.status == "rejected"


def test_generate_patches_stage_does_not_modify_original_and_leaves_pending(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    source_file = project / "app.py"
    original_code = "def vulnerable():\n    return eval('1 + 1')\n"
    source_file.write_text(original_code, encoding="utf-8")

    finding = make_finding("app.py", 2, "B307", "eval('1 + 1')", "f1")
    mock_llm = MockLLM(PatchResponse(
        patched_code="def vulnerable():\n    return 2\n",
        explanation="Avoid eval by returning constant.",
    ))

    patches, errors = generate_patches_stage(project, [finding], llm_client=mock_llm)

    assert len(patches) == 1
    assert errors == []
    assert patches[0].file == "app.py"
    assert patches[0].status == "pending"
    assert "Avoid eval" in patches[0].explanation
    # Verify original file was not modified
    assert source_file.read_text(encoding="utf-8") == original_code


def test_apply_patches_stage_applies_only_approved_patches(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app_file = project / "app.py"
    util_file = project / "util.py"

    orig_app = "def run():\n    return 'app_orig'\n"
    orig_util = "def util():\n    return 'util_orig'\n"
    app_file.write_text(orig_app, encoding="utf-8")
    util_file.write_text(orig_util, encoding="utf-8")

    app_patch = Patch(
        file="app.py",
        original_code=orig_app,
        patched_code="def run():\n    return 'app_patched'\n",
        diff="--- app",
        explanation="Patch app",
        addressed_finding_ids=["f_app"],
        status="approved",  # Explicitly approved
    )
    util_patch = Patch(
        file="util.py",
        original_code=orig_util,
        patched_code="def util():\n    return 'util_patched'\n",
        diff="--- util",
        explanation="Patch util",
        addressed_finding_ids=["f_util"],
        status="rejected",  # Explicitly rejected
    )

    workdir = tmp_path / "workdir"
    patched_dir, errors = apply_patches_stage(project, [app_patch, util_patch], workdir=workdir, require_approval=True)

    assert errors == []
    assert patched_dir is not None
    assert patched_dir.exists()

    # Approved patch was applied in the isolated copy
    assert (patched_dir / "app.py").read_text(encoding="utf-8") == "def run():\n    return 'app_patched'\n"
    # Rejected patch was NOT applied in the isolated copy
    assert (patched_dir / "util.py").read_text(encoding="utf-8") == orig_util

    # Original project files are completely untouched
    assert app_file.read_text(encoding="utf-8") == orig_app
    assert util_file.read_text(encoding="utf-8") == orig_util


def test_pending_patches_are_never_applied(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app_file = project / "app.py"
    orig_app = "def run():\n    return 'pending_test'\n"
    app_file.write_text(orig_app, encoding="utf-8")

    pending_patch = Patch(
        file="app.py",
        original_code=orig_app,
        patched_code="def run():\n    return 'should_never_apply'\n",
        diff="--- app",
        explanation="Pending patch",
        addressed_finding_ids=["f1"],
        status="pending",  # Still pending review
    )

    workdir = tmp_path / "workdir"
    patched_dir, errors = apply_patches_stage(project, [pending_patch], workdir=workdir, require_approval=True)

    # Must return None and report that no approved patches were available
    assert patched_dir is None
    assert any("No approved patches to apply" in err for err in errors)
    # Original project untouched
    assert app_file.read_text(encoding="utf-8") == orig_app


def test_rejected_patches_are_never_applied(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app_file = project / "app.py"
    orig_app = "def run():\n    return 'rejected_test'\n"
    app_file.write_text(orig_app, encoding="utf-8")

    rejected_patch = Patch(
        file="app.py",
        original_code=orig_app,
        patched_code="def run():\n    return 'should_never_apply'\n",
        diff="--- app",
        explanation="Rejected patch",
        addressed_finding_ids=["f1"],
        status="rejected",  # Rejected by human
    )

    workdir = tmp_path / "workdir"
    patched_dir, errors = apply_patches_stage(project, [rejected_patch], workdir=workdir, require_approval=True)

    assert patched_dir is None
    assert any("No approved patches to apply" in err for err in errors)
    assert app_file.read_text(encoding="utf-8") == orig_app


def test_prevent_accidental_duplicate_application_when_rerun(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app_file = project / "app.py"
    orig_app = "x = 1\n"
    app_file.write_text(orig_app, encoding="utf-8")

    patch = Patch(
        file="app.py",
        original_code=orig_app,
        patched_code="x = 2\n",
        diff="---",
        explanation="fix",
        addressed_finding_ids=["f1"],
        status="approved",
    )
    workdir = tmp_path / "workdir"

    # First run succeeds
    first_dir, errors1 = apply_patches_stage(project, [patch], workdir=workdir, require_approval=True)
    assert errors1 == []
    assert first_dir is not None

    # Attempting to re-apply into the same destination prevents clobbering
    second_dir, errors2 = apply_patches_stage(project, [patch], workdir=workdir, require_approval=True)
    assert second_dir is None
    assert any("already exists" in err for err in errors2)


def test_failed_patch_generation_preserves_errors_and_conservative_status(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app_file = project / "app.py"
    app_file.write_text("def test(): pass\n", encoding="utf-8")
    finding = make_finding("app.py", 1, "B101", "assert False", "f1")

    # LLM fails with an exception
    mock_llm = MockLLM(error=RuntimeError("API quota exceeded"))
    patches, errors = generate_patches_stage(project, [finding], llm_client=mock_llm)

    assert patches == []
    assert len(errors) == 1
    assert "Patch generation failed for app.py" in errors[0]

    # When report is finalized, the failure must prevent SAFE status
    report = PipelineReport(
        project=str(project),
        findings=[finding],
        confirmed=[finding],
        patches=patches,
        errors=errors,
        diff=None,
        regression=None,
    )
    final = finalize_report(report)
    assert final.final_status == "RISKY"
    assert any("remain without a completed patched rescan" in r for r in final.status_reasons)


def test_partial_approval_diff_classification_and_conservative_status():
    f_app = make_finding("app.py", 10, "B608", "execute(query)", "f-app")
    f_util = make_finding("util.py", 20, "B307", "eval(code)", "f-util")

    # Before findings: both f_app and f_util
    before = [f_app, f_util]
    # In after rescan: f_app was fixed by approved patch; f_util was NOT fixed because patch was rejected
    after = [f_util]

    diff = classify(before, after)
    assert len(diff.fixed) == 1
    assert diff.fixed[0].id == "f-app"
    assert len(diff.remaining) == 1
    assert diff.remaining[0].id == "f-util"
    assert len(diff.new) == 0

    # Final report must be RISKY because confirmed vulnerability f-util remains
    report = PipelineReport(
        project="demo",
        findings=before,
        confirmed=before,
        diff=diff,
        regression=RegressionResult(
            original=SecureTestResult(passed=2),
            patched=SecureTestResult(passed=2),
            newly_failing=[],
        ),
    )
    final = finalize_report(report)
    assert final.final_status == "RISKY"
    assert any("remain after patching" in r for r in final.status_reasons)


def test_distinguish_remediated_vs_disappeared_findings():
    f_targeted = make_finding("app.py", 5, "B608", "query = f'SELECT {name}'", "f-target")
    f_incidental = make_finding("app.py", 15, "B105", "SECRET = 'x'", "f-incidental")

    applied_patch = Patch(
        file="app.py",
        original_code="code",
        patched_code="code",
        diff="diff",
        explanation="Fixed SQL injection",
        addressed_finding_ids=["f-target"],  # Only targeted f-target
        status="approved",
    )

    # In rescan, both disappeared from scanner output
    diff = DiffResult(fixed=[f_targeted, f_incidental], remaining=[], new=[])

    addressed_ids = set(applied_patch.addressed_finding_ids)
    remediated = [f for f in diff.fixed if f.id in addressed_ids]
    disappeared = [f for f in diff.fixed if f.id not in addressed_ids]

    assert len(remediated) == 1
    assert remediated[0].id == "f-target"
    assert len(disappeared) == 1
    assert disappeared[0].id == "f-incidental"

