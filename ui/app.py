"""Streamlit UI for the 9-Stage SecureLens Platform: GitHub Import, Semgrep*, Evidence-Grounded Triage, Code Explorer, & HITL Patching."""

from __future__ import annotations

import sys
import uuid
from collections import Counter
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st

from securelens.config import load_settings
from securelens.context import extract_context
from securelens.llm import LLMClient
from securelens.models import Finding, PipelineReport
from securelens.pipeline import (
    apply_patches_stage,
    diff_stage,
    generate_patches_stage,
    regression_stage,
    scan_stage,
    triage_stage,
)
from securelens.regression import run_tests
from securelens.repo_manager import (
    checkout_branch,
    clone_or_open_repo,
    list_branches,
    list_imported_repos,
    list_repo_files,
    read_repo_file,
)
from securelens.report import finalize_report
from securelens.scanner import SEMGREP_STAR_DIR

st.set_page_config(page_title="SecureLens", page_icon="🔎", layout="wide")
st.title("🔎 SecureLens")
st.caption(
    "9-Stage AI-Assisted Security Review: GitHub Repository Import · Semgrep* Enhanced Detection · "
    "Evidence-Grounded Triage · Interactive Code Explorer · HITL Sandbox Verification"
)

SAMPLE_ROOT = Path(__file__).resolve().parents[1] / "samples"
JAVA_SAMPLE_NAMES = ["cmdi_java_app", "xxe_java_app", "deser_java_app", "path_ssrf_java_app"]
PYTHON_SAMPLE_NAMES = ["sqli_app", "cmdi_app", "secrets_deser_app", "wow_app"]
ALL_SAMPLES = JAVA_SAMPLE_NAMES + PYTHON_SAMPLE_NAMES
settings = load_settings()


def _format_code_with_highlight(content: str, highlight_line: int | None = None) -> str:
    """Format file lines with 1-based line numbers and an optional `>>>` marker on the target line."""
    lines = content.splitlines()
    formatted: list[str] = []
    for idx, text in enumerate(lines, start=1):
        marker = ">>>" if highlight_line == idx else "   "
        formatted.append(f"{marker} {idx:4d} | {text}")
    return "\n".join(formatted)


def _language_for_file(filename: str) -> str:
    suffix = Path(filename).suffix.lower()
    return {
        ".java": "java",
        ".py": "python",
        ".xml": "xml",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".json": "json",
        ".md": "markdown",
        ".sh": "bash",
    }.get(suffix, "text")


with st.sidebar:
    st.header("1. GitHub Repository Import")
    with st.expander("➕ Import GitHub Repository", expanded=False):
        gh_url = st.text_input("GitHub Repository URL", placeholder="https://github.com/owner/repo")
        gh_branch = st.text_input("Branch (optional)", placeholder="main")
        if st.button("Clone & Import Repository", use_container_width=True):
            try:
                with st.spinner("Validating URL and cloning into isolated workspace…"):
                    imported = clone_or_open_repo(gh_url, branch=gh_branch or None)
                    st.session_state["sl_active_source_type"] = "Imported GitHub Repo"
                    st.session_state["sl_selected_repo_id"] = imported.id
                    st.success(f"Imported {imported.label} ({imported.current_branch})")
                    st.rerun()
            except Exception as exc:
                st.error(f"Import failed: {exc}")

    imported_repos = list_imported_repos()
    if imported_repos:
        st.caption("Managed Workspace Repositories:")
        for repo in imported_repos:
            if st.button(f"📁 {repo.label} [{repo.current_branch}]", key=f"side_repo_{repo.id}", use_container_width=True):
                st.session_state["sl_active_source_type"] = "Imported GitHub Repo"
                st.session_state["sl_selected_repo_id"] = repo.id
                st.rerun()

    st.divider()
    st.header("2. Select Active Workspace")
    source_options = ["Semgrep* Java Samples", "Imported GitHub Repo", "Python Samples", "Custom Local Folder"]
    default_idx = 1 if (st.session_state.get("sl_active_source_type") == "Imported GitHub Repo" and imported_repos) else 0
    source_type = st.selectbox("Workspace source", source_options, index=default_idx)
    st.session_state["sl_active_source_type"] = source_type

    active_repo = None
    if source_type == "Semgrep* Java Samples":
        selection = st.selectbox("Java Sample Project (Semgrep*)", JAVA_SAMPLE_NAMES)
        project = SAMPLE_ROOT / selection
    elif source_type == "Imported GitHub Repo":
        if not imported_repos:
            st.warning("No GitHub repositories imported yet. Use 'Import GitHub Repository' above.")
            project = SAMPLE_ROOT / JAVA_SAMPLE_NAMES[0]
        else:
            repo_map = {r.id: r for r in imported_repos}
            default_id = st.session_state.get("sl_selected_repo_id")
            if default_id not in repo_map:
                default_id = imported_repos[0].id
            chosen_label = st.selectbox(
                "Imported Repository",
                options=list(repo_map.keys()),
                index=list(repo_map.keys()).index(default_id),
                format_func=lambda rid: repo_map[rid].label,
            )
            st.session_state["sl_selected_repo_id"] = chosen_label
            active_repo = repo_map[chosen_label]
            project = Path(active_repo.local_path)

            branches = list_branches(project)
            cur_branch = active_repo.current_branch if active_repo.current_branch in branches else branches[0]
            selected_branch = st.selectbox("Branch", branches, index=branches.index(cur_branch))
            if selected_branch != active_repo.current_branch:
                if st.button(f"Switch to branch `{selected_branch}`"):
                    try:
                        checkout_branch(project, selected_branch)
                        st.success(f"Switched to {selected_branch}")
                        st.rerun()
                    except Exception as exc:
                        st.error(str(exc))
    elif source_type == "Python Samples":
        selection = st.selectbox("Python Sample Project", PYTHON_SAMPLE_NAMES)
        project = SAMPLE_ROOT / selection
    else:
        custom_path = st.text_input("Local project folder", value=str(SAMPLE_ROOT / JAVA_SAMPLE_NAMES[0]))
        project = Path(custom_path).expanduser()

    st.divider()
    st.header("3. Scanner & AI Settings")
    model_name = st.text_input("Gemini model", value=settings.gemini_model)
    offline = st.checkbox("Offline mode (cache only)", value=settings.offline)
    rule_count = len(list(SEMGREP_STAR_DIR.glob("*.yaml"))) if SEMGREP_STAR_DIR.is_dir() else 0
    st.caption(f"Scanner: **Semgrep\*** ({rule_count} enhanced Java rules) + applicable Bandit")
    st.caption(f"Model: `{model_name}`")

project = project.resolve()
project_key = str(project)
if st.session_state.get("sl_project_key") != project_key:
    for key in list(st.session_state):
        if key.startswith("sl_") and key not in {"sl_project_key", "sl_active_source_type", "sl_selected_repo_id"}:
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
    return st.session_state.get(f"sl_{name}", default)


def _store(name: str, value) -> None:
    st.session_state[f"sl_{name}"] = value


def _current_report() -> PipelineReport:
    scan = _get_state("scan", {})
    triage = _get_state("triage", {})
    proposed = _get_state("proposed_patches", {})
    fixes = _get_state("fixes", {})
    patches = fixes.get("patches", proposed.get("patches", []))
    verdicts = triage.get("verdicts", [])
    verdict_by_id = {v.finding_id: v for v in verdicts}
    findings = scan.get("findings", [])
    uncertain = [f for f in findings if f.id in verdict_by_id and verdict_by_id[f.id].status == "uncertain"]
    report = PipelineReport(
        project=str(project),
        patched_project=fixes.get("patched_project"),
        findings=findings,
        verdicts=verdicts,
        confirmed=triage.get("confirmed", []),
        dismissed=triage.get("dismissed", []),
        uncertain=uncertain,
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


# =====================================================================
# STAGE 1: REPOSITORY FILE EXPLORER & INTERACTIVE CODE VIEWER
# =====================================================================
st.subheader(f"Stage 1 — Repository Workspace & Code Explorer (`{project.name}`)")
repo_files = list_repo_files(project)
if not repo_files:
    st.warning(f"No readable source files found in `{project}`.")
else:
    col_tree, col_viewer = st.columns([1, 2.4])
    focused_file = st.session_state.get("sl_focused_file")
    if focused_file not in repo_files:
        focused_file = repo_files[0]
        st.session_state["sl_focused_file"] = focused_file
    focused_line = st.session_state.get("sl_focused_line")

    with col_tree:
        st.markdown("**📂 Repository Structure**")
        selected_file = st.selectbox(
            "Select file to inspect",
            repo_files,
            index=repo_files.index(focused_file),
            key="sl_file_selector",
        )
        if selected_file != focused_file:
            st.session_state["sl_focused_file"] = selected_file
            st.session_state["sl_focused_line"] = None
            focused_file = selected_file
            focused_line = None

        with st.container(height=240):
            for rel_path in repo_files:
                icon = "☕" if rel_path.endswith(".java") else ("🐍" if rel_path.endswith(".py") else "📄")
                label = f"**{icon} {rel_path}**" if rel_path == focused_file else f"{icon} {rel_path}"
                if st.button(label, key=f"tree_btn_{rel_path}", use_container_width=True):
                    st.session_state["sl_focused_file"] = rel_path
                    st.session_state["sl_focused_line"] = None
                    st.rerun()

    with col_viewer:
        header_text = f"**📄 Code Viewer: `{focused_file}`**"
        if focused_line:
            header_text += f" — 🎯 **Highlighted Finding at Line {focused_line}** (`>>>`)"
        st.markdown(header_text)
        try:
            file_content = read_repo_file(project, focused_file)
            if focused_line:
                lines = file_content.splitlines()
                if 1 <= focused_line <= len(lines):
                    st.warning(f"🎯 **Line {focused_line}:** `{lines[focused_line - 1].strip()}`")
            numbered_code = _format_code_with_highlight(file_content, highlight_line=focused_line)
            st.code(numbered_code, language=_language_for_file(focused_file))
        except Exception as exc:
            st.error(f"Could not read file: {exc}")

st.divider()

# =====================================================================
# STAGE 2 & 3: STATIC SCAN (Semgrep* + Bandit) & EVIDENCE-GROUNDED TRIAGE
# =====================================================================
scan_state = _get_state("scan", None)
col_run_btn, col_reset_btn = st.columns([1, 3])
if col_run_btn.button("🚀 Run Semgrep* Scan & AI Triage", type="primary", disabled=(scan_state is not None)):
    try:
        with st.spinner("Running Semgrep* enhanced rules, AST/Java method context extraction, and Gemini triage…"):
            findings, scan_errors = scan_stage(project)
            verdicts, confirmed, dismissed, unresolved, triage_errors = triage_stage(
                findings, project, llm_client=llm_client,
            )
            baseline = run_tests(project)
            baseline_errors = []
            if baseline.errors and baseline.status != "no_tests":
                baseline_errors.append(f"Original tests reported {baseline.errors} error(s): {baseline.raw_output_tail}")
            _store("scan", {"findings": findings, "errors": scan_errors + baseline_errors, "baseline": baseline})
            _store(
                "triage",
                {
                    "verdicts": verdicts,
                    "confirmed": confirmed,
                    "dismissed": dismissed,
                    "unresolved": unresolved,
                    "errors": triage_errors,
                },
            )
            _store("triage_done_key", triage_key)
            st.rerun()
    except Exception as exc:
        st.error(f"Scan stage failed ({type(exc).__name__}): {exc}")

if scan_state is not None:
    if col_reset_btn.button("🔄 Reset Scan & Re-run"):
        for k in ("sl_scan", "sl_triage", "sl_triage_done_key", "sl_proposed_patches", "sl_fixes"):
            st.session_state.pop(k, None)
        st.rerun()

scan_state = _get_state("scan", None)
triage_state = _get_state("triage", {})

if scan_state is not None:
    findings: list[Finding] = scan_state.get("findings", [])
    st.subheader("Stage 2 — Static Security Scan Results (Semgrep* + Applicable Bandit)")
    by_tool = Counter(item.tool for item in findings)
    by_severity = Counter(item.severity for item in findings)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Findings", len(findings))
    c2.metric("Semgrep* Alerts", by_tool.get("semgrep", 0))
    c3.metric("Bandit Alerts", by_tool.get("bandit", 0))
    c4.metric("High Severity", by_severity.get("HIGH", 0))
    st.caption(
        "By severity: "
        + ", ".join(f"{name}: {by_severity.get(name, 0)}" for name in ("HIGH", "MEDIUM", "LOW"))
    )

    if not findings:
        st.info("No findings were returned by the configured scanners.")

    # Re-run triage if model/offline setting changed
    triage_done = _get_state("triage_done_key", None) == triage_key
    if not triage_done and st.button("Re-run AI Triage with current model settings"):
        with st.spinner("Triaging findings…"):
            verdicts, confirmed, dismissed, unresolved, triage_errors = triage_stage(
                findings, project, llm_client=llm_client,
            )
            triage_state = {
                "verdicts": verdicts,
                "confirmed": confirmed,
                "dismissed": dismissed,
                "unresolved": unresolved,
                "errors": triage_errors,
            }
            _store("triage", triage_state)
            _store("triage_done_key", triage_key)
            st.rerun()

    triage_state = _get_state("triage", {})
    verdicts_by_id = {item.finding_id: item for item in triage_state.get("verdicts", [])}

    # Separate Confirmed (high-confidence true positive) vs Uncertain (low-confidence or unresolved, retained conservatively)
    all_confirmed: list[Finding] = triage_state.get("confirmed", [])
    dismissed_list: list[Finding] = triage_state.get("dismissed", [])
    uncertain_list: list[Finding] = [
        f for f in all_confirmed if (verdicts_by_id.get(f.id) and verdicts_by_id[f.id].status == "uncertain")
    ]
    strict_confirmed_list: list[Finding] = [
        f for f in all_confirmed if f not in uncertain_list
    ]

    # =====================================================================
    # STAGE 3 & STAGE 4: VULNERABILITY DASHBOARD & CODE VISUALIZATION
    # =====================================================================
    st.subheader("Stage 3 & 4 — Evidence-Grounded AI Triage & Vulnerability Dashboard")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("🚨 Confirmed (True Positives)", len(strict_confirmed_list))
    m2.metric("⚠️ Uncertain (Retained Conservatively)", len(uncertain_list))
    m3.metric("✅ Dismissed (False Positives Removed)", len(dismissed_list))
    m4.metric("🔧 Active for Remediation", len(all_confirmed))

    tab_all, tab_conf, tab_unc, tab_dism = st.tabs([
        f"📊 All Findings Dashboard ({len(findings)})",
        f"🚨 Confirmed ({len(strict_confirmed_list)})",
        f"⚠️ Uncertain ({len(uncertain_list)})",
        f"✅ Dismissed ({len(dismissed_list)})",
    ])

    def _render_finding_cards(group: list[Finding], tab_prefix: str) -> None:
        if not group:
            st.caption("No findings in this category.")
            return
        for idx, finding in enumerate(group):
            verdict = verdicts_by_id.get(finding.id)
            status_tag = verdict.status.upper() if verdict else "UNASSESSED"
            badge_icon = "🚨" if status_tag == "CONFIRMED" else ("⚠️" if status_tag == "UNCERTAIN" else "✅")
            cwe_label = finding.cwe or "CWE-Unmapped"
            title = (
                f"{badge_icon} [{status_tag}] {finding.file}:{finding.line} — "
                f"{finding.rule_id} | {cwe_label} ({finding.severity})"
            )
            with st.expander(title, expanded=(status_tag in {"CONFIRMED", "UNCERTAIN"} and idx == 0)):
                top_c1, top_c2 = st.columns([3, 1])
                with top_c1:
                    st.markdown(f"**File & Line:** `{finding.file}` (Line **{finding.line}**)")
                    st.markdown(f"**CWE:** `{cwe_label}` | **Severity:** `{finding.severity}` | **Scanner:** `{finding.tool}` (`{finding.rule_id}`)")
                    st.markdown(f"**Scanner Message:** {finding.message}")
                with top_c2:
                    if st.button(
                        f"🎯 Highlight in Code Viewer (Line {finding.line})",
                        key=f"jump_{tab_prefix}_{finding.id}_{idx}",
                        use_container_width=True,
                    ):
                        st.session_state["sl_focused_file"] = finding.file
                        st.session_state["sl_focused_line"] = finding.line
                        st.rerun()

                if verdict:
                    grounding_badge = (
                        "✅ Evidence Verified in Repository"
                        if verdict.grounding_verified
                        else "⚠️ Unverified / Fallback Grounding (Retained Conservatively)"
                    )
                    st.info(
                        f"**AI Assessment:** `{status_tag}` (Confidence: **{verdict.confidence:.2f}**) — {grounding_badge}\n\n"
                        f"**Reasoning:** {verdict.reason}\n\n"
                        f"**Cited Evidence (Line {verdict.evidence_line or finding.line}):** `{verdict.evidence_snippet or finding.snippet}`"
                    )

                try:
                    context = extract_context(finding, project)
                    ctx_tab1, ctx_tab2, ctx_tab3 = st.tabs([
                        f"Highlighted Source Context (Line {finding.line})",
                        f"Enclosing Method/Function ({context.function_name or 'module-level'})",
                        "Imports / Package",
                    ])
                    with ctx_tab1:
                        st.code(context.numbered_lines, language="text")
                    with ctx_tab2:
                        st.code(context.source, language=_language_for_file(finding.file))
                    with ctx_tab3:
                        st.code("\n".join(context.imports) or "(none)", language=_language_for_file(finding.file))
                except Exception as exc:
                    st.error(f"Context unavailable ({type(exc).__name__}): {exc}")

    with tab_all:
        _render_finding_cards(findings, "all")
    with tab_conf:
        _render_finding_cards(strict_confirmed_list, "conf")
    with tab_unc:
        _render_finding_cards(uncertain_list, "unc")
    with tab_dism:
        _render_finding_cards(dismissed_list, "dism")

    st.divider()

    # =====================================================================
    # STAGE 5 & STAGE 6: PATCH GENERATION & HUMAN-IN-THE-LOOP APPROVAL
    # =====================================================================
    st.subheader("Stage 5 & 6 — Patch Generation & Human-in-the-Loop (HITL) Approval")
    proposed_state = _get_state("proposed_patches", None)
    fixes_state = _get_state("fixes", None)

    if proposed_state is None:
        can_generate = len(all_confirmed) > 0
        if not can_generate:
            st.info("No confirmed or uncertain vulnerabilities requiring patches.")
        if st.button("✨ Generate Proposed Patches with Gemini", disabled=not can_generate, type="primary"):
            try:
                with st.spinner("Generating complete-file patches with Gemini (without modifying original source)…"):
                    patches, gen_errors = generate_patches_stage(
                        project, all_confirmed, llm_client=llm_client,
                    )
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
            st.info("No patches were generated for the active findings.")
        else:
            pending_count = sum(1 for p in patches if p.status == "pending")
            approved_count = sum(1 for p in patches if p.status == "approved")
            rejected_count = sum(1 for p in patches if p.status == "rejected")

            col_m1, col_m2, col_m3, col_m4 = st.columns(4)
            col_m1.metric("Proposed Patches", len(patches))
            col_m2.metric("⏳ Pending Review", pending_count)
            col_m3.metric("✅ Approved", approved_count)
            col_m4.metric("❌ Rejected", rejected_count)

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

            findings_by_id = {f.id: f for f in findings}
            for idx, patch in enumerate(patches):
                status_icon = "⏳" if patch.status == "pending" else ("✅" if patch.status == "approved" else "❌")
                status_label = patch.status.upper()
                expander_title = f"{status_icon} [{status_label}] {patch.file}: {patch.explanation}"

                with st.expander(expander_title, expanded=(fixes_state is None and patch.status == "pending")):
                    st.markdown(f"**Target file:** `{patch.file}` | **Review status:** `{status_label}`")
                    st.markdown(f"**AI Explanation:** {patch.explanation}")

                    st.markdown("**Addressed security findings:**")
                    addressed = [findings_by_id[fid] for fid in patch.addressed_finding_ids if fid in findings_by_id]
                    for item in addressed:
                        st.write(f"- Line {item.line} [{item.severity}] ({item.rule_id} / {item.cwe or 'CWE'}): {item.message}")

                    lang = _language_for_file(patch.file)
                    diff_tab, before_tab, after_tab = st.tabs(["Unified Diff", "Original (Before)", "Proposed (After)"])
                    with diff_tab:
                        st.code(patch.diff or "(No source differences generated)", language="diff")
                    with before_tab:
                        st.code(patch.original_code, language=lang)
                    with after_tab:
                        st.code(patch.patched_code, language=lang)

                    if fixes_state is None:
                        st.markdown("**Human Review Decision:**")
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
                        st.caption(f"Review status is locked as **{status_label}** during isolated sandbox validation.")

            approved_patches = [p for p in patches if p.status == "approved"]
            if fixes_state is None:
                if not approved_patches:
                    st.warning("⚠️ No patches have been approved yet. Inspect each proposed patch above and click **Approve** before applying.")
                    st.button("Apply approved patches to isolated sandbox & validate", disabled=True)
                else:
                    st.info(
                        f"Ready to apply **{len(approved_patches)} approved patch(es)** (out of {len(patches)} total) "
                        "to an isolated copy in `workdir/`. Original repository files will remain untouched."
                    )
                    if st.button("🛡️ Apply Approved Patches to Isolated Sandbox & Validate", type="primary"):
                        try:
                            with st.spinner("Cloning into isolated sandbox, rescanning with Semgrep*, and running regression checks…"):
                                run_workdir = Path.cwd() / "workdir" / f"ui_{uuid.uuid4().hex[:10]}"
                                patched_dir, apply_errors = apply_patches_stage(
                                    project, approved_patches, workdir=run_workdir, require_approval=True,
                                )
                                diff = None
                                regression = None
                                stage_errors = list(apply_errors)
                                if patched_dir is not None:
                                    diff, diff_errors = diff_stage(
                                        findings, patched_dir, original_project=project,
                                    )
                                    stage_errors.extend(diff_errors)
                                    regression, regression_errors = regression_stage(
                                        project, patched_dir, baseline=scan_state.get("baseline"),
                                    )
                                    stage_errors.extend(regression_errors)
                                _store(
                                    "fixes",
                                    {
                                        "patches": patches,
                                        "applied_patches": approved_patches,
                                        "patched_project": str(patched_dir) if patched_dir else None,
                                        "diff": diff,
                                        "regression": regression,
                                        "errors": stage_errors,
                                    },
                                )
                                st.rerun()
                        except Exception as exc:
                            st.error(f"Patch application failed ({type(exc).__name__}): {exc}")
            else:
                st.caption(f"Isolated Sandbox Copy: `{fixes_state.get('patched_project')}`")
                if st.button("Reset patch review & re-evaluate"):
                    st.session_state.pop("sl_fixes", None)
                    st.session_state.pop("sl_proposed_patches", None)
                    st.rerun()

    # =====================================================================
    # STAGE 7, 8 & 9: POST-PATCH RESCAN, REGRESSION TESTING & FINAL VERDICT
    # =====================================================================
    fixes_state = _get_state("fixes", None)
    if fixes_state is not None:
        st.divider()
        st.subheader("Stage 7 — Post-Patch Security Rescan (Semgrep* Before vs. After)")
        diff = fixes_state.get("diff")
        if diff:
            applied = fixes_state.get("applied_patches", [])
            addressed_ids = {fid for p in applied for fid in p.addressed_finding_ids}

            fixed_tab, remaining_tab, new_tab = st.tabs([
                f"✅ Fixed ({len(diff.fixed)})",
                f"⚠️ Remaining ({len(diff.remaining)})",
                f"🚨 NEW ({len(diff.new)})",
            ])
            with fixed_tab:
                if not diff.fixed:
                    st.caption("No fixed findings.")
                else:
                    for finding in diff.fixed:
                        if finding.id in addressed_ids:
                            st.success(
                                f"✅ **[Remediated by patch]** {finding.file}:{finding.line} — "
                                f"{finding.rule_id} ({finding.cwe or 'CWE'}): {finding.message}"
                            )
                        else:
                            st.info(
                                f"🔍 **[Disappeared from scan]** {finding.file}:{finding.line} — "
                                f"{finding.rule_id}: {finding.message}"
                            )
            with remaining_tab:
                if not diff.remaining:
                    st.caption("No remaining findings.")
                else:
                    for finding in diff.remaining:
                        unapproved = [
                            p for p in fixes_state.get("patches", [])
                            if p.status != "approved" and finding.id in p.addressed_finding_ids
                        ]
                        note = f" (Patch was {unapproved[0].status.upper()})" if unapproved else ""
                        st.warning(f"⚠️ {finding.file}:{finding.line} — {finding.rule_id}: {finding.message}{note}")
            with new_tab:
                if not diff.new:
                    st.caption("No new findings.")
                else:
                    for finding in diff.new:
                        st.error(f"🚨 **[NEW finding introduced]** {finding.file}:{finding.line} — {finding.rule_id}: {finding.message}")
        else:
            st.warning("Patched rescan did not produce a complete comparison.")

        st.subheader("Stage 8 — Functional Regression Testing")
        regression = fixes_state.get("regression")
        if regression:
            orig_status = getattr(regression.original, "status", "ran")
            if orig_status in {"no_tests", "unavailable"}:
                st.warning(
                    "⚠️ **No compatible test suite was executed in this repository.** "
                    "Per SecureLens safety policy, absence of tests is recorded as `INCOMPLETE` rather than `SAFE`."
                )
            else:
                left, right = st.columns(2)
                left.metric("Original Tests Passed", regression.original.passed)
                right.metric("Patched Tests Passed", regression.patched.passed)
                st.write(
                    f"Failed before/after: {regression.original.failed}/{regression.patched.failed}; "
                    f"errors before/after: {regression.original.errors}/{regression.patched.errors}"
                )
                if getattr(regression, "fixed_tests", None):
                    st.success("✅ **Remediated test failures:** " + ", ".join(regression.fixed_tests))
                if regression.newly_failing:
                    st.error("🚨 **Newly failing tests:** " + ", ".join(regression.newly_failing))
                else:
                    st.success("No newly failing tests were observed.")
        else:
            st.warning("Patched regression tests did not complete.")

        st.subheader("Stage 9 — Final Assessment Verdict")
        report = _current_report()
        if report.final_status == "SAFE":
            st.success("🟢 **SAFE** — " + " ".join(report.status_reasons))
        elif report.final_status == "RISKY":
            st.error("🔴 **RISKY** — " + " ".join(report.status_reasons))
        else:
            st.warning("🟡 **INCOMPLETE** — " + " ".join(report.status_reasons))
        for error in report.errors:
            st.error(error)
else:
    st.info("Inspect files in the Code Explorer above or click **🚀 Run Semgrep* Scan & AI Triage** to start the 9-stage pipeline.")
