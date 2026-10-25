"""Orchestrate scan, triage, patch, rescan, and regression stages."""

from __future__ import annotations

import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

from .config import load_settings
from .context import extract_context
from .differ import classify
from .fixer import apply_patches, generate_patch
from .llm import LLMClient
from .models import DiffResult, Finding, Patch, PipelineReport, RegressionResult, TestResult, Verdict
from .regression import compare_tests, run_tests
from .report import finalize_report
from .scanner import scan_project
from .triage import is_confirmed, triage


def scan_stage(project_dir: str | Path) -> tuple[list[Finding], list[str]]:
    """Run both configured static scanners and retain all diagnostics."""
    return scan_project(project_dir)


def triage_stage(
    findings: list[Finding], project_dir: str | Path, *,
    llm_client: LLMClient | None = None,
) -> tuple[list[Verdict], list[Finding], list[Finding], list[Finding], list[str]]:
    """Extract context and triage each finding, confirming failures conservatively."""
    verdicts: list[Verdict] = []
    confirmed: list[Finding] = []
    dismissed: list[Finding] = []
    unresolved: list[Finding] = []
    errors: list[str] = []
    threshold = load_settings().triage_threshold
    for finding in findings:
        try:
            context = extract_context(finding, project_dir)
            verdict = triage(finding, context, llm_client=llm_client, threshold=threshold)
        except Exception as exc:
            verdict = Verdict(
                finding_id=finding.id, is_true_positive=True, confidence=0,
                reason=f"Triage was unresolved ({type(exc).__name__}); the finding is conservatively confirmed.",
            )
        verdicts.append(verdict)
        if verdict.reason.startswith("Triage was unresolved"):
            unresolved.append(finding)
            errors.append(f"Triage unresolved for {finding.id}: {verdict.reason}")
            confirmed.append(finding)
        elif is_confirmed(verdict, threshold):
            confirmed.append(finding)
        else:
            dismissed.append(finding)
    return verdicts, confirmed, dismissed, unresolved, errors


def fix_stage(
    project_dir: str | Path, confirmed: list[Finding], *,
    llm_client: LLMClient | None = None, workdir: str | Path | None = None,
) -> tuple[list[Patch], Path | None, list[str]]:
    """Generate per-file patches and apply valid changes to an isolated copy."""
    root = Path(project_dir).resolve()
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in confirmed:
        grouped[finding.file].append(finding)
    patches: list[Patch] = []
    errors: list[str] = []
    for relative, items in sorted(grouped.items()):
        try:
            patches.append(generate_patch(root / relative, items, project_dir=root, llm_client=llm_client))
        except Exception as exc:
            errors.append(f"Patch generation failed for {relative} ({type(exc).__name__}).")
    try:
        patched_dir = apply_patches(root, patches, workdir=workdir)
        return patches, patched_dir, errors
    except Exception as exc:
        errors.append(f"Patch application failed ({type(exc).__name__}): {exc}")
        return patches, None, errors


def diff_stage(
    before: list[Finding], patched_project: str | Path, *,
    original_project: str | Path | None = None,
) -> tuple[DiffResult | None, list[str]]:
    """Rescan a patched project and classify fixed, remaining, and new findings."""
    findings, errors = scan_project(patched_project)
    if errors and not findings:
        return None, errors
    if original_project is not None:
        _attach_function_context(before, original_project)
    _attach_function_context(findings, patched_project)
    return classify(before, findings), errors


def regression_stage(
    original_project: str | Path, patched_project: str | Path, *,
    baseline: TestResult | None = None, timeout: int | None = None,
) -> tuple[RegressionResult, list[str]]:
    """Compare baseline and patched tests by failing test identity."""
    original = baseline or run_tests(original_project, timeout=timeout)
    patched = run_tests(patched_project, timeout=timeout)
    result = compare_tests(original, patched)
    errors = []
    if original.errors:
        errors.append(f"Original test run reported {original.errors} error(s).")
    if patched.errors:
        errors.append(f"Patched test run reported {patched.errors} error(s).")
    return result, errors


def run_pipeline(
    project_dir: str | Path,
    *,
    do_fix: bool = True,
    offline: bool | None = None,
    llm_client: LLMClient | None = None,
    workdir: str | Path | None = None,
    timeout: int | None = None,
) -> PipelineReport:
    """Execute the complete assessment while preserving partial results."""
    root = Path(project_dir).resolve()
    report = PipelineReport(project=str(root))
    client = llm_client or LLMClient(load_settings(offline=offline))
    timings: dict[str, float] = {}

    started = time.perf_counter()
    report.findings, errors = scan_stage(root)
    report.errors.extend(errors)
    timings["scan"] = time.perf_counter() - started

    started = time.perf_counter()
    (report.verdicts, report.confirmed, report.dismissed,
     report.unresolved, errors) = triage_stage(report.findings, root, llm_client=client)
    report.errors.extend(errors)
    timings["triage"] = time.perf_counter() - started

    started = time.perf_counter()
    baseline = run_tests(root, timeout=timeout)
    if baseline.errors:
        report.errors.append(f"Original test run reported {baseline.errors} error(s): {baseline.raw_output_tail}")
    timings["baseline_tests"] = time.perf_counter() - started

    patched_dir: Path | None = None
    if do_fix:
        started = time.perf_counter()
        run_workdir = Path(workdir) if workdir is not None else Path.cwd() / "workdir" / f"run_{root.name}_{uuid.uuid4().hex[:10]}"
        report.patches, patched_dir, errors = fix_stage(root, report.confirmed, llm_client=client, workdir=run_workdir)
        report.errors.extend(errors)
        timings["patch"] = time.perf_counter() - started
        if patched_dir:
            report.patched_project = str(patched_dir)
            started = time.perf_counter()
            report.diff, errors = diff_stage(report.findings, patched_dir, original_project=root)
            report.errors.extend(errors)
            timings["diff"] = time.perf_counter() - started
            started = time.perf_counter()
            report.regression, errors = regression_stage(root, patched_dir, baseline=baseline, timeout=timeout)
            report.errors.extend(errors)
            timings["regression"] = time.perf_counter() - started
    else:
        report.errors.append("Patch, rescan, and patched regression stages were skipped because do_fix=False.")

    report.timings = timings
    return finalize_report(report)


def _attach_function_context(findings: list[Finding], project_dir: str | Path) -> None:
    """Populate function names so fingerprints match across scan stages."""
    for finding in findings:
        try:
            extract_context(finding, project_dir)
        except (OSError, ValueError):
            # Missing context must not erase a scanner finding; it remains reportable.
            continue
