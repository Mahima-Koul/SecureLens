"""Streamlit UI for the staged SecureLens assessment pipeline with Human-in-the-Loop patch review."""

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
from securelens.pipeline import (
    apply_patches_stage,
    diff_stage,
    generate_patches_stage,
    regression_stage,
    scan_stage,
    triage_stage,
)
from securelens.report import finalize_report


st.set_page_config(page_title="SecureLens", page_icon="🔎", layout="wide")
st.title("SecureLens")
st.caption("Human-in-the-Loop AI-assisted Python security review with isolated patch validation.")

SAMPLE_ROOT = Path(__file__).resolve().parents[1] / "samples"
SAMPLE_NAMES = ["sqli_app", "cmdi_app", "secrets_deser_app", "wow_app"]
settings = load_settings()

with st.sidebar:
    st.header("Project")
    selection = st.selectbox("Sample project", [*SAMPLE_NAMES, "Custom folder"])
    custom_path = st.text_input("Local project folder", value=str(SAMPLE_ROOT / SAMPLE_NAMES[0]))
    project = (SAMPLE_ROOT / selection) if selection != "Custom folder" else Path(custom_path).expanduser()
    model_name = st.text_input("Gemini model", value=settings.gemini_model)
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
    st.session_state.pop("sl_proposed_patches", None)
    st.session_state.pop("sl_fixes", None)
st.session_state["sl_config_key"] = triage_key

client_settings = replace(load_settings(offline=offline), gemini_model=model_name)
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
    proposed = _get_state("proposed_patches", {})
    fixes = _get_state("fixes", {})
    patches = fixes.get("patches", proposed.get("patches", []))
    report = PipelineReport(
        project=str(project),
        patched_project=fixes.get("patched_project"),
        findings=scan.get("findings", []),
        verdicts=triage.get("verdicts", []),
        confirmed=triage.get("confirmed", []),
        dismissed=triage.get("dismissed", []),
        unresolved=triage.get("unresolved", []),
        patches=patches,
        diff=fixes.get("diff"),
        regression=fixes.get("regression"),
        errors=(
            scan.get("errors", [])
            + triage.get("errors", [])
            + proposed.get("errors", [])
            + fixes.get("errors", [])
        ),
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

    # Human-in-the-Loop Patch Review Workflow
    st.subheader("3. Proposed patches (Human Review)")
    proposed_state = _get_state("proposed_patches", None)
    fixes_state = _get_state("fixes", None)

    if proposed_state is None:
        confirmed_findings = triage_state.get("confirmed", [])
        can_generate = len(confirmed_findings) > 0
        if not can_generate:
            st.info("No confirmed vulnerabilities requiring patches.")
        if st.button("Generate proposed patches", disabled=not can_generate, type="primary"):
            try:
                with st.spinner("Generating proposed patches with Gemini (without modifying original source)…"):
                    patches, gen_errors = generate_patches_stage(
                        project, confirmed_findings, llm_client=llm_client,
                    )
                    # All proposed patches initially require explicit human approval (pending status)
                    for patch in patches:
                        patch.status = "pending"
                    _store("proposed_patches", {"patches": patches, "errors": gen_errors})
                    st.rerun()
            except Exception as exc:
                st.error(f"Patch generation failed ({type(exc).__name__}): {exc}")

    proposed_state = _get_state("proposed_patches", None)
    if proposed_state is not None:
        patches = proposed_state.get("patches", [])
        gen_errors = proposed_state.get("errors", [])
        for err in gen_errors:
            st.error(err)

        if not patches:
            st.info("No patches were generated for the confirmed findings.")
        else:
            pending_count = sum(1 for p in patches if p.status == "pending")
            approved_count = sum(1 for p in patches if p.status == "approved")
            rejected_count = sum(1 for p in patches if p.status == "rejected")

            col_m1, col_m2, col_m3, col_m4 = st.columns(4)
            col_m1.metric("Proposed patches", len(patches))
            col_m2.metric("⏳ Pending review", pending_count)
            col_m3.metric("✅ Approved", approved_count)
            col_m4.metric("❌ Rejected", rejected_count)

            # Quick bulk controls when review is still open
            if fixes_state is None and len(patches) > 1:
                b_col1, b_col2, _ = st.columns([1, 1, 2])
                if b_col1.button("Approve all patches"):
                    for p in patches:
                        p.status = "approved"
                    _store("proposed_patches", proposed_state)
                    st.rerun()
                if b_col2.button("Reject all patches"):
                    for p in patches:
                        p.status = "rejected"
                    _store("proposed_patches", proposed_state)
                    st.rerun()

            findings_by_id = {f.id: f for f in scan_state.get("findings", [])}
            for idx, patch in enumerate(patches):
                status_icon = "⏳" if patch.status == "pending" else ("✅" if patch.status == "approved" else "❌")
                status_label = patch.status.upper()
                expander_title = f"{status_icon} [{status_label}] {patch.file}: {patch.explanation}"

                with st.expander(expander_title, expanded=(fixes_state is None and patch.status == "pending")):
                    st.markdown(f"**Target file:** `{patch.file}`")
                    st.markdown(f"**Review status:** `{status_label}`")
                    st.markdown(f"**Explanation:** {patch.explanation}")

                    st.markdown("**Addressed security findings:**")
                    addressed = [findings_by_id[fid] for fid in patch.addressed_finding_ids if fid in findings_by_id]
                    if addressed:
                        for item in addressed:
                            st.write(f"- Line {item.line} [{item.severity}] ({item.rule_id}): {item.message}")
                    else:
                        st.caption("None or unresolved finding IDs.")

                    diff_tab, before_tab, after_tab = st.tabs(["Unified Diff", "Original (Before)", "Proposed (After)"])
                    with diff_tab:
                        st.code(patch.diff or "(No source differences generated)", language="diff")
                    with before_tab:
                        st.code(patch.original_code, language="python")
                    with after_tab:
                        st.code(patch.patched_code, language="python")

                    if fixes_state is None:
                        st.markdown("**Review Decision:**")
                        c_app, c_rej, c_pen = st.columns(3)
                        if c_app.button("✅ Approve", key=f"btn_app_{idx}_{patch.file}", disabled=(patch.status == "approved")):
                            patch.status = "approved"
                            _store("proposed_patches", proposed_state)
                            st.rerun()
                        if c_rej.button("❌ Reject", key=f"btn_rej_{idx}_{patch.file}", disabled=(patch.status == "rejected")):
                            patch.status = "rejected"
                            _store("proposed_patches", proposed_state)
                            st.rerun()
                        if c_pen.button("⏳ Mark Pending", key=f"btn_pen_{idx}_{patch.file}", disabled=(patch.status == "pending")):
                            patch.status = "pending"
                            _store("proposed_patches", proposed_state)
                            st.rerun()
                    else:
                        st.caption(f"Review status is locked as **{status_label}** during validation.")

            st.subheader("4. Apply approved patches & validate")
            approved_patches = [p for p in patches if p.status == "approved"]

            if fixes_state is None:
                if not approved_patches:
                    st.warning("⚠️ No patches have been approved yet. Inspect each proposed patch above and click **Approve** before applying.")
                    st.button("Apply approved patches and validate", disabled=True)
                else:
                    st.info(f"Ready to apply **{len(approved_patches)} approved patch(es)** (out of {len(patches)} total) to an isolated copy. The original project will remain untouched.")
                    if st.button("Apply approved patches and validate", type="primary"):
                        try:
                            with st.spinner("Applying only approved patches to isolated working copy, rescanning, and running regression tests…"):
                                run_workdir = Path.cwd() / "workdir" / f"ui_{uuid.uuid4().hex[:10]}"
                                patched_dir, apply_errors = apply_patches_stage(
                                    project, approved_patches, workdir=run_workdir, require_approval=True,
                                )
                                diff = None
                                regression = None
                                stage_errors = list(apply_errors)
                                if patched_dir is not None:
                                    diff, diff_errors = diff_stage(
                                        scan_state.get("findings", []), patched_dir, original_project=project,
                                    )
                                    stage_errors.extend(diff_errors)
                                    regression, regression_errors = regression_stage(
                                        project, patched_dir, baseline=scan_state.get("baseline"),
                                    )
                                    stage_errors.extend(regression_errors)
                                _store("fixes", {
                                    "patches": patches,
                                    "applied_patches": approved_patches,
                                    "patched_project": str(patched_dir) if patched_dir else None,
                                    "diff": diff,
                                    "regression": regression,
                                    "errors": stage_errors,
                                })
                                st.rerun()
                        except Exception as exc:
                            st.error(f"Patch application failed ({type(exc).__name__}): {exc}")
            else:
                st.caption(f"Validation completed in isolated copy: `{fixes_state.get('patched_project')}`")
                applied_count = len(fixes_state.get("applied_patches", []))
                st.write(f"Applied **{applied_count} approved patch(es)**.")
                if st.button("Reset patch review & re-evaluate"):
                    st.session_state.pop("sl_fixes", None)
                    st.session_state.pop("sl_proposed_patches", None)
                    st.rerun()

    fixes_state = _get_state("fixes", None)
    if fixes_state is not None:
        st.subheader("5. Before/after findings")
        diff = fixes_state.get("diff")
        if diff:
            applied = fixes_state.get("applied_patches", [])
            addressed_ids = {fid for p in applied for fid in p.addressed_finding_ids}

            fixed_tab, remaining_tab, new_tab = st.tabs([
                f"Fixed ({len(diff.fixed)})", f"Remaining ({len(diff.remaining)})", f"NEW ({len(diff.new)})",
            ])
            with fixed_tab:
                if not diff.fixed:
                    st.caption("No fixed findings.")
                else:
                    st.caption("Findings are distinguished between directly addressed remediations and findings that disappeared without a targeted patch:")
                    for finding in diff.fixed:
                        if finding.id in addressed_ids:
                            st.success(f"✅ **[Remediated by patch]** {finding.file}:{finding.line} — {finding.rule_id}: {finding.message}")
                        else:
                            st.info(f"🔍 **[Disappeared from scan]** {finding.file}:{finding.line} — {finding.rule_id}: {finding.message} *(disappeared from scanner output; not directly targeted)*")

            with remaining_tab:
                if not diff.remaining:
                    st.caption("No remaining findings.")
                else:
                    for finding in diff.remaining:
                        unapproved_patches = [
                            p for p in fixes_state.get("patches", [])
                            if p.status != "approved" and finding.id in p.addressed_finding_ids
                        ]
                        note = f" (Patch was {unapproved_patches[0].status.upper()})" if unapproved_patches else ""
                        st.warning(f"⚠️ {finding.file}:{finding.line} — {finding.rule_id}: {finding.message}{note}")

            with new_tab:
                if not diff.new:
                    st.caption("No new findings.")
                else:
                    for finding in diff.new:
                        st.error(f"🚨 **[NEW finding introduced]** {finding.file}:{finding.line} — {finding.rule_id}: {finding.message}")
        else:
            st.warning("Patched rescan did not produce a complete comparison.")

        st.subheader("6. Regression tests")
        regression = fixes_state.get("regression")
        if regression:
            left, right = st.columns(2)
            left.metric("Original tests passed", regression.original.passed)
            right.metric("Patched tests passed", regression.patched.passed)
            st.write(f"Failed before/after: {regression.original.failed}/{regression.patched.failed}; "
                     f"errors before/after: {regression.original.errors}/{regression.patched.errors}")
            if getattr(regression, "fixed_tests", None):
                st.success("✅ **Remediated test failures (verified fixed by patch):** " + ", ".join(regression.fixed_tests))
            if regression.newly_failing:
                st.error("Newly failing tests: " + ", ".join(regression.newly_failing))
            else:
                st.success("No newly failing tests were observed.")
        else:
            st.warning("Patched regression tests did not complete.")

        st.subheader("7. Final assessment")
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
