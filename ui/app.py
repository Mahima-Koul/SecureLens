"""Streamlit UI for the staged SecureLens assessment pipeline."""

from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import replace
from pathlib import Path

import streamlit as st

from securelens.config import load_settings
from securelens.context import extract_context
from securelens.llm import LLMClient
from securelens.models import PipelineReport
from securelens.pipeline import diff_stage, fix_stage, regression_stage, scan_stage, triage_stage
from securelens.report import finalize_report


st.set_page_config(page_title="SecureLens", page_icon="🔎", layout="wide")
st.title("SecureLens")
st.caption("Check whether AI-assisted code fixes introduce new security issues or regressions.")

SAMPLE_ROOT = Path(__file__).resolve().parents[1] / "samples"
SAMPLE_NAMES = ["sqli_app", "cmdi_app", "secrets_deser_app", "wow_app"]
settings = load_settings()

with st.sidebar:
    st.header("Project")
    selection = st.selectbox("Sample project", [*SAMPLE_NAMES, "Custom folder"])
    custom_path = st.text_input("Local project folder", value=str(SAMPLE_ROOT / SAMPLE_NAMES[0]))
    project = (SAMPLE_ROOT / selection) if selection != "Custom folder" else Path(custom_path).expanduser()
    model_name = st.text_input("OpenAI model", value=settings.openai_model)
    offline = st.checkbox("Offline mode (cache only)", value=settings.offline)
    st.caption(f"Configured model: `{model_name}`")
    st.caption("Offline mode never sends an API request; cache misses are reported.")

project = project.resolve()
project_key = str(project)
if st.session_state.get("sl_project_key") != project_key:
    for key in list(st.session_state):
        if key.startswith("sl_") and key != "sl_project_key":
            del st.session_state[key]
    st.session_state["sl_project_key"] = project_key

triage_key = f"{model_name}|{offline}"
if st.session_state.get("sl_config_key") not in (None, triage_key):
    st.session_state.pop("sl_triage", None)
    st.session_state.pop("sl_triage_done_key", None)
    st.session_state.pop("sl_fixes", None)
st.session_state["sl_config_key"] = triage_key

client_settings = replace(load_settings(offline=offline), openai_model=model_name)
llm_client = LLMClient(client_settings)


def _get_state(name: str, default):
    """Read a pipeline stage from Streamlit state."""
    return st.session_state.get(f"sl_{name}", default)


def _store(name: str, value) -> None:
    """Persist a completed stage so Streamlit reruns do not repeat it."""
    st.session_state[f"sl_{name}"] = value


def _current_report() -> PipelineReport:
    """Build a report from the completed UI stages and determine its status."""
    scan = _get_state("scan", {})
    triage = _get_state("triage", {})
    fixes = _get_state("fixes", {})
    report = PipelineReport(
        project=str(project), patched_project=fixes.get("patched_project"),
        findings=scan.get("findings", []), verdicts=triage.get("verdicts", []),
        confirmed=triage.get("confirmed", []), dismissed=triage.get("dismissed", []),
        unresolved=triage.get("unresolved", []), patches=fixes.get("patches", []),
        diff=fixes.get("diff"), regression=fixes.get("regression"),
        errors=(scan.get("errors", []) + triage.get("errors", []) + fixes.get("errors", [])),
        timings={},
    )
    return finalize_report(report)


scan_state = _get_state("scan", None)
scan_disabled = scan_state is not None
if st.button("Run scan and triage", type="primary", disabled=scan_disabled):
    try:
        with st.spinner("Running Semgrep, Bandit, context extraction, and triage…"):
            findings, scan_errors = scan_stage(project)
            verdicts, confirmed, dismissed, unresolved, triage_errors = triage_stage(
                findings, project, llm_client=llm_client,
            )
            baseline = None
            baseline_errors = []
            from securelens.regression import run_tests
            baseline = run_tests(project)
            if baseline.errors:
                baseline_errors.append(f"Original tests reported {baseline.errors} error(s): {baseline.raw_output_tail}")
            _store("scan", {"findings": findings, "errors": scan_errors + baseline_errors, "baseline": baseline})
            _store("triage", {"verdicts": verdicts, "confirmed": confirmed, "dismissed": dismissed,
                               "unresolved": unresolved, "errors": triage_errors})
            _store("triage_done_key", triage_key)
    except Exception as exc:
        st.error(f"Scan stage failed ({type(exc).__name__}): {exc}")

scan_state = _get_state("scan", None)
triage_state = _get_state("triage", {})
if scan_state is not None:
    findings = scan_state.get("findings", [])
    st.subheader("1. Scan results")
    by_tool = Counter(item.tool for item in findings)
    by_severity = Counter(item.severity for item in findings)
    columns = st.columns(4)
    columns[0].metric("Findings", len(findings))
    columns[1].metric("Semgrep", by_tool.get("semgrep", 0))
    columns[2].metric("Bandit", by_tool.get("bandit", 0))
    columns[3].metric("High severity", by_severity.get("HIGH", 0))
    st.caption("By severity: " + ", ".join(f"{name}: {by_severity.get(name, 0)}" for name in ("HIGH", "MEDIUM", "LOW")))
    if not findings:
        st.info("No findings were returned. Review scanner diagnostics before treating this as a clean result.")

    st.subheader("2. Triage")
    triage_done = _get_state("triage_done_key", None) == triage_key
    if not triage_done and st.button("Run triage with current settings"):
        try:
            with st.spinner("Extracting context and triaging findings…"):
                verdicts, confirmed, dismissed, unresolved, triage_errors = triage_stage(
                    scan_state.get("findings", []), project, llm_client=llm_client,
                )
                triage_state = {"verdicts": verdicts, "confirmed": confirmed, "dismissed": dismissed,
                                "unresolved": unresolved, "errors": triage_errors}
                _store("triage", triage_state)
                _store("triage_done_key", triage_key)
        except Exception as exc:
            st.error(f"Triage stage failed ({type(exc).__name__}): {exc}")
    triage_state = _get_state("triage", {})
    confirmed_tab, dismissed_tab = st.tabs([f"Confirmed ({len(triage_state.get('confirmed', []))})",
                                           f"Dismissed ({len(triage_state.get('dismissed', []))})"])
    verdicts_by_id = {item.finding_id: item for item in triage_state.get("verdicts", [])}
    for tab, group in ((confirmed_tab, triage_state.get("confirmed", [])),
                       (dismissed_tab, triage_state.get("dismissed", []))):
        with tab:
            if not group:
                st.caption("None")
            for finding in group:
                verdict = verdicts_by_id.get(finding.id)
                with st.expander(f"{finding.rule_id} — {finding.file}:{finding.line} ({finding.severity})"):
                    st.write(finding.message)
                    if verdict:
                        st.write(f"Confidence: {verdict.confidence:.2f}")
                        st.write(f"Reason: {verdict.reason}")
                    try:
                        context = extract_context(finding, project)
                        st.caption("Imports")
                        st.code("\n".join(context.imports) or "(none)", language="python")
                        st.caption("Enclosing function or nearby source")
                        st.code(context.source, language="python")
                        st.caption("Numbered lines")
                        st.code(context.numbered_lines, language="text")
                    except Exception as exc:
                        st.error(f"Context unavailable ({type(exc).__name__}): {exc}")

    fixes_state = _get_state("fixes", None)
    st.subheader("3. Generate fixes")
    if st.button("Generate fixes and run comparisons", disabled=fixes_state is not None):
        try:
            with st.spinner("Generating patches, rescanning, and running regression tests…"):
                patches, patched_dir, fix_errors = fix_stage(
                    project, triage_state.get("confirmed", []), llm_client=llm_client,
                    workdir=Path.cwd() / "workdir" / f"ui_{uuid.uuid4().hex[:10]}",
                )
                diff = None
                regression = None
                stage_errors = list(fix_errors)
                if patched_dir is not None:
                    diff, diff_errors = diff_stage(scan_state.get("findings", []), patched_dir,
                                                   original_project=project)
                    stage_errors.extend(diff_errors)
                    regression, regression_errors = regression_stage(
                        project, patched_dir, baseline=scan_state.get("baseline"),
                    )
                    stage_errors.extend(regression_errors)
                _store("fixes", {"patches": patches, "patched_project": str(patched_dir) if patched_dir else None,
                                  "diff": diff, "regression": regression, "errors": stage_errors})
        except Exception as exc:
            st.error(f"Fix stage failed ({type(exc).__name__}): {exc}")

    fixes_state = _get_state("fixes", None)
    if fixes_state is not None:
        if fixes_state.get("patched_project"):
            st.caption(f"Patched copy: `{fixes_state['patched_project']}`")
        for patch in fixes_state.get("patches", []):
            with st.expander(f"{patch.file}: {patch.explanation}"):
                st.code(patch.diff or "No source changes generated.", language="diff")
        st.subheader("4. Before/after findings")
        diff = fixes_state.get("diff")
        if diff:
            fixed_tab, remaining_tab, new_tab = st.tabs([
                f"Fixed ({len(diff.fixed)})", f"Remaining ({len(diff.remaining)})", f"NEW ({len(diff.new)})",
            ])
            for tab, title, group in ((fixed_tab, "Fixed", diff.fixed),
                                      (remaining_tab, "Remaining", diff.remaining),
                                      (new_tab, "NEW", diff.new)):
                with tab:
                    if not group:
                        st.caption(f"No {title.lower()} findings.")
                    for finding in group:
                        message = f"{finding.file}:{finding.line} — {finding.rule_id}: {finding.message}"
                        if title == "NEW":
                            st.error(message)
                        else:
                            st.write(message)
        else:
            st.warning("Patched rescan did not produce a complete comparison.")

        st.subheader("5. Regression tests")
        regression = fixes_state.get("regression")
        if regression:
            left, right = st.columns(2)
            left.metric("Original tests passed", regression.original.passed)
            right.metric("Patched tests passed", regression.patched.passed)
            st.write(f"Failed before/after: {regression.original.failed}/{regression.patched.failed}; "
                     f"errors before/after: {regression.original.errors}/{regression.patched.errors}")
            if regression.newly_failing:
                st.error("Newly failing tests: " + ", ".join(regression.newly_failing))
            else:
                st.success("No newly failing tests were observed.")
        else:
            st.warning("Patched regression tests did not complete.")

        st.subheader("6. Final assessment")
        report = _current_report()
        if report.final_status == "SAFE":
            st.success("SAFE — " + " ".join(report.status_reasons))
        elif report.final_status == "RISKY":
            st.error("RISKY — " + " ".join(report.status_reasons))
        else:
            st.warning("INCOMPLETE — " + " ".join(report.status_reasons))
        for error in report.errors:
            st.error(error)

if scan_state is None:
    st.info("Choose a sample or local Python project, then run the scan to begin.")
