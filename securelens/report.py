"""Final status rules and concise report rendering."""

from __future__ import annotations

from .differ import fingerprint
from .models import PipelineReport


def finalize_report(report: PipelineReport) -> PipelineReport:
    """Set SAFE/RISKY/INCOMPLETE from measured findings, tests, and stage errors."""
    reasons = []
    if report.diff and report.diff.new:
        reasons.append("The patched scan found new security findings.")
    if report.regression and report.regression.newly_failing:
        reasons.append("The patched project introduced newly failing tests.")
    if report.unresolved:
        reasons.append("One or more findings could not be safely dismissed.")
    if report.diff:
        remaining_fingerprints = {fingerprint(item) for item in report.diff.remaining}
        if any(fingerprint(item) in remaining_fingerprints for item in report.confirmed):
            reasons.append("One or more confirmed vulnerabilities remain after patching.")
    elif report.confirmed:
        reasons.append("Confirmed vulnerabilities remain without a completed patched rescan.")

    if reasons:
        report.final_status = "RISKY"
    elif report.errors or report.diff is None or report.regression is None:
        report.final_status = "INCOMPLETE"
        reasons.append("A required pipeline stage did not complete or produced insufficient evidence.")
    else:
        report.final_status = "SAFE"
        reasons.append("No new findings or newly failing tests were observed, and required stages completed.")
    report.status_reasons = reasons
    return report


def render_summary(report: PipelineReport) -> str:
    """Render a concise human-readable pipeline summary."""
    lines = [
        f"Project: {report.project}",
        f"Status: {report.final_status}",
        f"Findings: {len(report.findings)} total, {len(report.confirmed)} confirmed, "
        f"{len(report.dismissed)} dismissed, {len(report.unresolved)} unresolved",
    ]
    if report.diff:
        lines.append(f"After patch: {len(report.diff.fixed)} fixed, {len(report.diff.remaining)} remaining, {len(report.diff.new)} new")
    if report.regression:
        lines.append(f"Tests: {report.regression.original.passed} passed before, "
                     f"{report.regression.patched.passed} passed after, "
                     f"{len(report.regression.newly_failing)} newly failing")
    lines.extend(f"Reason: {reason}" for reason in report.status_reasons)
    lines.extend(f"Error: {error}" for error in report.errors)
    return "\n".join(lines)
