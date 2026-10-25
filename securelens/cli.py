"""SecureLens command line entry point."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import load_settings
from .llm import LLMClient
from .pipeline import run_pipeline, scan_stage, triage_stage
from .report import render_summary


def _render_scan(findings, verdicts, confirmed, dismissed, unresolved, errors) -> None:
    """Print triage results with reasons and scanner diagnostics."""
    verdict_by_id = {verdict.finding_id: verdict for verdict in verdicts}
    confirmed_ids = {finding.id for finding in confirmed}
    dismissed_ids = {finding.id for finding in dismissed}
    unresolved_ids = {finding.id for finding in unresolved}
    print(f"Findings: {len(findings)} total; {len(confirmed)} confirmed; {len(dismissed)} dismissed; {len(unresolved)} unresolved")
    for finding in findings:
        verdict = verdict_by_id.get(finding.id)
        label = "UNRESOLVED" if finding.id in unresolved_ids else "CONFIRMED" if finding.id in confirmed_ids else "DISMISSED" if finding.id in dismissed_ids else "UNASSESSED"
        confidence = f" ({verdict.confidence:.2f})" if verdict else ""
        reason = f" — {verdict.reason}" if verdict else ""
        print(f"[{label}]{confidence} {finding.file}:{finding.line} {finding.rule_id} [{finding.severity}] {finding.message}{reason}")
    for error in errors:
        print(f"ERROR: {error}")


def _exit_code(report) -> int:
    """Map final assessment status to a shell exit code."""
    return {"SAFE": 0, "RISKY": 1, "INCOMPLETE": 2}[report.final_status]


def main() -> int:
    """Run SecureLens scanning and full-pipeline commands."""
    parser = argparse.ArgumentParser(prog="securelens")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="scan a Python project")
    scan_parser.add_argument("project", type=Path)
    scan_parser.add_argument("--offline", action="store_true", help="use only cached LLM responses")
    run_parser = subparsers.add_parser("run", help="run the complete safety assessment")
    run_parser.add_argument("project", type=Path)
    run_parser.add_argument("--json", action="store_true", help="write the machine-readable report to stdout")
    run_parser.add_argument("--offline", action="store_true", help="use only cached LLM responses")
    args = parser.parse_args()
    if args.command == "scan":
        client = LLMClient(load_settings(offline=True if args.offline else None))
        findings, scan_errors = scan_stage(args.project)
        verdicts, confirmed, dismissed, unresolved, triage_errors = triage_stage(
            findings, args.project, llm_client=client,
        )
        _render_scan(findings, verdicts, confirmed, dismissed, unresolved, scan_errors + triage_errors)
        return 1 if scan_errors or unresolved else 0
    if args.command == "run":
        report = run_pipeline(args.project, offline=True if args.offline else None)
        if args.json:
            print(json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False))
        else:
            try:
                from rich.console import Console
                from rich.panel import Panel
                Console().print(Panel(render_summary(report), title=f"SecureLens: {report.final_status}"))
            except ImportError:
                print(render_summary(report))
        return _exit_code(report)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
