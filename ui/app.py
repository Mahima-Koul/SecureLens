"""Streamlit UI for SecureLens: GitHub Import, Semgrep*, Evidence-Grounded Triage, Code Explorer, & HITL Patching."""

from __future__ import annotations

import html
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

_DEPTH_CSS = "\n".join(
    f'.st-key-sl_tree_box [class*="st-key-dir_btn_d{d}__"],\n'
    f'.st-key-sl_tree_box [class*="st-key-tree_btn_d{d}__"] {{\n'
    f"    padding-left: {d * 16}px !important;\n"
    f"}}"
    for d in range(16)
)

st.html(
    f"""
<style>
.block-container {{
    padding-top: 3.75rem !important;
    padding-bottom: 2.2rem !important;
}}
[data-testid="stHeaderActionElements"] {{
    display: none !important;
}}
button[data-testid="stBaseButton-primary"] {{
    background-color: #238636 !important;
    border: 1px solid rgba(240, 246, 252, 0.14) !important;
    color: #ffffff !important;
    font-weight: 500 !important;
    border-radius: 6px !important;
}}
button[data-testid="stBaseButton-primary"]:hover {{
    background-color: #2ea043 !important;
    border-color: rgba(240, 246, 252, 0.22) !important;
}}
button[data-testid="stBaseButton-primary"]:disabled {{
    background-color: rgba(35, 134, 54, 0.35) !important;
    color: rgba(255, 255, 255, 0.55) !important;
    border-color: rgba(255, 255, 255, 0.08) !important;
}}
button[data-testid="stBaseButton-secondary"] {{
    background-color: rgba(255, 255, 255, 0.04) !important;
    border: 1px solid rgba(255, 255, 255, 0.14) !important;
    color: #e6edf3 !important;
    border-radius: 6px !important;
}}
button[data-testid="stBaseButton-secondary"]:hover {{
    background-color: rgba(255, 255, 255, 0.09) !important;
    border-color: rgba(255, 255, 255, 0.24) !important;
}}
button[data-baseweb="tab"][aria-selected="true"] {{
    color: #58a6ff !important;
}}
[data-baseweb="tab-highlight"] {{
    background-color: #58a6ff !important;
}}
.st-key-sl_tree_box [data-testid="stVerticalBlock"] {{
    gap: 0px !important;
}}
.st-key-sl_tree_box button[data-testid^="stBaseButton"] {{
    min-height: 26px !important;
    height: auto !important;
    padding: 2px 8px !important;
    margin: 1px 0 !important;
    font-size: 13px !important;
    line-height: 1.35 !important;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
    border-radius: 5px !important;
    justify-content: flex-start !important;
    text-align: left !important;
}}
.st-key-sl_tree_box button[data-testid^="stBaseButton"]:hover {{
    background: rgba(148, 163, 184, 0.14) !important;
}}
.st-key-sl_tree_box button[data-testid="stBaseButton-primary"] {{
    background: rgba(59, 130, 246, 0.22) !important;
    border: 1px solid rgba(59, 130, 246, 0.45) !important;
    color: inherit !important;
    font-weight: 600 !important;
}}
.st-key-sl_tree_box button[data-testid^="stBaseButton"] p {{
    margin: 0 !important;
    text-align: left !important;
    white-space: nowrap !important;
}}
{_DEPTH_CSS}
</style>
"""
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


def _render_code_viewer_html(
    content: str,
    *,
    highlight_line: int | None = None,
    font_size: int = 14,
) -> str:
    """Render line-numbered code HTML with zoomable font size and colored vulnerability line highlighting."""
    clamped_size = max(12, min(22, int(font_size)))
    lines = content.splitlines() or [""]
    rows: list[str] = []
    for idx, text in enumerate(lines, start=1):
        is_hit = highlight_line == idx
        row_style = (
            "display:flex;align-items:baseline;padding:2px 12px;"
            "background:linear-gradient(90deg,rgba(239,68,68,0.34) 0%,rgba(245,158,11,0.22) 100%);"
            "border-left:4px solid #ef4444;color:#fff7ed;font-weight:600;"
            if is_hit
            else "display:flex;align-items:baseline;padding:1px 12px;border-left:4px solid transparent;"
        )
        gutter_style = (
            "min-width:4.4em;text-align:right;padding-right:12px;user-select:none;flex-shrink:0;"
            + ("color:#fbbf24;font-weight:700;" if is_hit else "color:#64748b;")
        )
        marker = f"🎯 {idx}" if is_hit else str(idx)
        escaped_line = html.escape(text) if text else "&nbsp;"
        rows.append(
            f'<div style="{row_style}">'
            f'<span style="{gutter_style}">{marker}</span>'
            f'<span style="white-space:pre;">{escaped_line}</span>'
            f"</div>"
        )
    container_style = (
        "background:#161b22;color:#e6edf3;border:1px solid rgba(255,255,255,0.10);border-radius:8px;"
        "padding:10px 0;max-height:460px;overflow:auto;"
        "font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;"
        f"font-size:{clamped_size}px;line-height:1.55;"
    )
    return f'<div style="{container_style}">{"".join(rows)}</div>'


def _build_folder_tree(repo_files: list[str]) -> dict:
    """Build a VS Code-style nested folder/file tree, compacting single-child empty folder chains."""
    root: dict = {"dirs": {}, "files": []}
    for rel_path in sorted(repo_files):
        parts = rel_path.split("/")
        node = root
        for folder in parts[:-1]:
            node = node["dirs"].setdefault(folder, {"dirs": {}, "files": []})
        node["files"].append(rel_path)

    def _compact_and_sort(node: dict) -> dict:
        compacted_dirs: dict = {}
        for name, child in sorted(node["dirs"].items(), key=lambda item: item[0].lower()):
            cur_name = name
            cur_child = _compact_and_sort(child)
            while len(cur_child["dirs"]) == 1 and not cur_child["files"]:
                sub_name, sub_node = next(iter(cur_child["dirs"].items()))
                cur_name = f"{cur_name}/{sub_name}"
                cur_child = sub_node
            compacted_dirs[cur_name] = cur_child
        return {
            "dirs": dict(sorted(compacted_dirs.items(), key=lambda item: item[0].lower())),
            "files": sorted(node["files"], key=lambda path: path.rsplit("/", 1)[-1].lower()),
        }

    return _compact_and_sort(root)


def _pick_default_file(repo_files: list[str]) -> str:
    """Prefer a primary source file (.java/.py) over metadata or rule files on initial load."""
    for ext in (".java", ".py"):
        for rel_path in repo_files:
            if rel_path.endswith(ext) and not rel_path.startswith("semgreph_data/"):
                return rel_path
    return repo_files[0]


def _collect_all_folder_keys(tree: dict, prefix: str = "") -> list[str]:
    """Return every compacted folder key in a folder tree."""
    keys: list[str] = []
    for folder_name, child in tree["dirs"].items():
        key = f"{prefix}/{folder_name}" if prefix else folder_name
        keys.append(key)
        keys.extend(_collect_all_folder_keys(child, key))
    return keys


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


def _render_kpi_cards_html(cards: list[dict[str, str]]) -> str:
    """Render a clean, neutral row of security KPI cards with subtle status dots."""
    tiles: list[str] = []
    for card in cards:
        dot_color = html.escape(card.get("dot", "#8b949e"))
        title = html.escape(card["title"])
        value = html.escape(str(card["value"]))
        subtitle = html.escape(card["subtitle"])
        dot_html = (
            f'<span style="width:7px;height:7px;border-radius:50%;background:{dot_color};'
            f'display:inline-block;margin-right:7px;"></span>'
            if card.get("dot")
            else ""
        )
        tiles.append(
            '<div style="background:rgba(255,255,255,0.025);border:1px solid rgba(255,255,255,0.09);'
            'border-radius:8px;padding:14px 16px;">'
            f'<div style="display:flex;align-items:center;font-size:12.5px;font-weight:500;color:#8b949e;">'
            f'{dot_html}<span>{title}</span></div>'
            f'<div style="font-size:26px;font-weight:600;color:#f0f6fc;line-height:1.2;margin:6px 0 3px 0;'
            f'font-variant-numeric:tabular-nums;">{value}</div>'
            f'<div style="font-size:12px;color:#6e7681;">{subtitle}</div>'
            "</div>"
        )
    return (
        '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));'
        'gap:10px;margin:4px 0 10px 0;">'
        + "".join(tiles)
        + "</div>"
    )


def _render_breakdown_bar_html(
    label: str,
    summary_text: str,
    segments: list[tuple[str, int, str]],
) -> str:
    """Render a quiet, minimal segmented breakdown strip."""
    total = sum(count for _, count, _ in segments)
    legend = "".join(
        f'<span style="display:inline-flex;align-items:center;gap:5px;font-size:12px;color:#8b949e;">'
        f'<span style="width:6px;height:6px;border-radius:50%;background:{html.escape(color)};display:inline-block;"></span>'
        f'<span>{html.escape(name)} <strong style="color:#e6edf3;font-weight:600;">{count}</strong></span>'
        f"</span>"
        for name, count, color in segments
    )
    if total > 0:
        bar_parts = "".join(
            f'<div style="width:{(count / total) * 100:.2f}%;background:{html.escape(color)};height:100%;"></div>'
            for _, count, color in segments
            if count > 0
        )
    else:
        bar_parts = '<div style="width:100%;background:rgba(255,255,255,0.06);height:100%;"></div>'

    return (
        '<div style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.08);'
        'border-radius:8px;padding:10px 14px;margin:0 0 14px 0;">'
        '<div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:8px;margin-bottom:8px;">'
        f'<div style="font-size:12.5px;font-weight:500;color:#c9d1d9;">{html.escape(label)}'
        f' <span style="font-weight:400;color:#6e7681;margin-left:8px;">{html.escape(summary_text)}</span></div>'
        f'<div style="display:flex;flex-wrap:wrap;gap:14px;">{legend}</div>'
        "</div>"
        '<div style="display:flex;height:4px;border-radius:999px;overflow:hidden;background:rgba(255,255,255,0.06);">'
        f"{bar_parts}"
        "</div>"
        "</div>"
    )


SAMPLE_DESCRIPTIONS = {
    "cmdi_java_app": "OS Command Injection (CWE-78)",
    "xxe_java_app": "XML External Entity (CWE-611)",
    "deser_java_app": "Unsafe Deserialization (CWE-502)",
    "path_ssrf_java_app": "Path Traversal & SSRF (CWE-22 / CWE-918)",
    "sqli_app": "SQL Injection (Bandit B608)",
    "cmdi_app": "Command Injection (Bandit B602/B605)",
    "secrets_deser_app": "Hard-coded Secrets & Pickle",
    "wow_app": "Dynamic Evaluation (eval)",
}

with st.sidebar:
    st.subheader("Workspace")
    imported_repos = list_imported_repos()
    source_options = [
        "Java Samples (Semgrep*)",
        "GitHub Repository",
        "Python Samples (Bandit)",
        "Local Folder",
    ]
    saved_source = st.session_state.get("sl_active_source_type", source_options[0])
    if saved_source not in source_options:
        saved_source = source_options[0]
    source_type = st.selectbox(
        "Source",
        source_options,
        index=source_options.index(saved_source),
    )
    st.session_state["sl_active_source_type"] = source_type

    active_repo = None
    if source_type == "Java Samples (Semgrep*)":
        selection = st.selectbox("Java sample", JAVA_SAMPLE_NAMES)
        st.caption(SAMPLE_DESCRIPTIONS.get(selection, ""))
        project = SAMPLE_ROOT / selection
    elif source_type == "GitHub Repository":
        if imported_repos:
            repo_map = {r.id: r for r in imported_repos}
            default_id = st.session_state.get("sl_selected_repo_id")
            if default_id not in repo_map:
                default_id = imported_repos[0].id
            chosen_label = st.selectbox(
                "Repository",
                options=list(repo_map.keys()),
                index=list(repo_map.keys()).index(default_id),
                format_func=lambda rid: f"{repo_map[rid].owner}/{repo_map[rid].name}",
            )
            st.session_state["sl_selected_repo_id"] = chosen_label
            active_repo = repo_map[chosen_label]
            project = Path(active_repo.local_path)

            branches = list_branches(project)
            cur_branch = active_repo.current_branch if active_repo.current_branch in branches else branches[0]
            selected_branch = st.selectbox("Branch", branches, index=branches.index(cur_branch))
            if selected_branch != active_repo.current_branch:
                if st.button(f"Switch to {selected_branch}", use_container_width=True):
                    try:
                        checkout_branch(project, selected_branch)
                        st.success(f"Switched to {selected_branch}")
                        st.rerun()
                    except Exception as exc:
                        st.error(str(exc))
        else:
            st.caption("No repositories imported yet. Import one below.")
            project = SAMPLE_ROOT / JAVA_SAMPLE_NAMES[0]
    elif source_type == "Python Samples (Bandit)":
        selection = st.selectbox("Python sample", PYTHON_SAMPLE_NAMES)
        st.caption(SAMPLE_DESCRIPTIONS.get(selection, ""))
        project = SAMPLE_ROOT / selection
    else:
        custom_path = st.text_input("Folder path", value=str(SAMPLE_ROOT / JAVA_SAMPLE_NAMES[0]))
        project = Path(custom_path).expanduser()

    with st.expander("➕ Import GitHub Repository", expanded=(source_type == "GitHub Repository" and not imported_repos)):
        gh_url = st.text_input("Repository URL", placeholder="https://github.com/owner/repo")
        gh_branch = st.text_input("Branch (optional)", placeholder="main")
        if st.button("Clone & Open", use_container_width=True):
            try:
                with st.spinner("Cloning repository into isolated workspace…"):
                    imported = clone_or_open_repo(gh_url, branch=gh_branch or None)
                    st.session_state["sl_active_source_type"] = "GitHub Repository"
                    st.session_state["sl_selected_repo_id"] = imported.id
                    st.success(f"Imported {imported.owner}/{imported.name} ({imported.current_branch})")
                    st.rerun()
            except Exception as exc:
                st.error(f"Import failed: {exc}")

    st.divider()
    st.subheader("Settings")
    model_name = st.text_input("Gemini model", value=settings.gemini_model)
    offline = st.checkbox("Offline mode (cache only)", value=settings.offline)
    rule_count = len(list(SEMGREP_STAR_DIR.glob("*.yaml"))) if SEMGREP_STAR_DIR.is_dir() else 0
    st.caption(f"Scanners: Semgrep* ({rule_count} Java rules) & Bandit")

project = project.resolve()
project_key = str(project)
if st.session_state.get("sl_project_key") != project_key:
    for key in list(st.session_state):
        if key.startswith("sl_") and key not in {
            "sl_project_key",
            "sl_active_source_type",
            "sl_selected_repo_id",
            "sl_code_font_size",
        }:
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
repo_files = list_repo_files(project)
file_word = "file" if len(repo_files) == 1 else "files"
branch_tag = (
    f'<span style="border:1px solid rgba(255,255,255,0.12);background:rgba(255,255,255,0.04);'
    f'color:#c9d1d9;padding:4px 10px;border-radius:6px;font-size:12px;">branch: {html.escape(active_repo.current_branch)}</span>'
    if active_repo is not None
    else ""
)
mode_dot = "#3fb950" if offline else "#58a6ff"
mode_label = "Offline cache" if offline else "Live API"
st.html(
    f"""
<div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:12px;
background:#161b22;border:1px solid rgba(255,255,255,0.12);border-left:3px solid #2f81f7;
border-radius:10px;padding:16px 20px;margin-bottom:16px;">
  <div>
    <div style="font-size:24px;font-weight:600;color:#f0f6fc;letter-spacing:-0.015em;line-height:1.25;">
      🔎 SecureLens
    </div>
    <div style="font-size:13px;color:#8b949e;margin-top:4px;">
      Static security analysis, evidence-grounded triage, and isolated patch verification
    </div>
  </div>
  <div style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;">
    <span style="border:1px solid rgba(255,255,255,0.12);background:rgba(255,255,255,0.04);color:#e6edf3;padding:4px 10px;border-radius:6px;font-size:12px;">
      {html.escape(project.name)} · {len(repo_files)} {file_word}
    </span>
    {branch_tag}
    <span style="border:1px solid rgba(255,255,255,0.12);background:rgba(255,255,255,0.04);color:#c9d1d9;padding:4px 10px;border-radius:6px;font-size:12px;">
      <span style="color:{mode_dot};">●</span> {mode_label} · {html.escape(model_name)}
    </span>
  </div>
</div>
"""
)
st.subheader("Repository Explorer")
if not repo_files:
    st.warning(f"No readable source files found in `{project}`.")
else:
    col_tree, col_viewer = st.columns([1.05, 2.35])
    focused_file = st.session_state.get("sl_focused_file")
    if focused_file not in repo_files:
        focused_file = _pick_default_file(repo_files)
        st.session_state["sl_focused_file"] = focused_file
    focused_line = st.session_state.get("sl_focused_line")

    with col_tree:
        st.markdown("**📂 Folder Tree**")

        def _on_file_selector_change() -> None:
            st.session_state["sl_focused_file"] = st.session_state["sl_file_selector"]
            st.session_state["sl_focused_line"] = None

        st.session_state["sl_file_selector"] = focused_file
        st.selectbox(
            "Find file",
            repo_files,
            key="sl_file_selector",
            on_change=_on_file_selector_change,
            label_visibility="collapsed",
        )

        tree = _build_folder_tree(repo_files)
        all_folder_keys = _collect_all_folder_keys(tree)
        if "sl_expanded_folders" not in st.session_state:
            initial_expanded = {"__root__"}
            initial_expanded.update(k for k in all_folder_keys if focused_file.startswith(f"{k}/"))
            st.session_state["sl_expanded_folders"] = initial_expanded
            st.session_state["sl_tree_revealed_file"] = focused_file
        elif st.session_state.get("sl_tree_revealed_file") != focused_file:
            st.session_state["sl_expanded_folders"].add("__root__")
            st.session_state["sl_expanded_folders"].update(
                k for k in all_folder_keys if focused_file.startswith(f"{k}/")
            )
            st.session_state["sl_tree_revealed_file"] = focused_file

        expanded_folders: set[str] = st.session_state["sl_expanded_folders"]

        def _render_tree_node(
            node: dict,
            prefix: str = "",
            depth: int = 1,
        ) -> None:
            for folder_name, child in node["dirs"].items():
                folder_key = f"{prefix}/{folder_name}" if prefix else folder_name
                is_open = folder_key in expanded_folders
                arrow = "▾ 📂" if is_open else "▸ 📁"
                if st.button(
                    f"{arrow} {folder_name}",
                    key=f"dir_btn_d{depth}__{folder_key}",
                    type="tertiary",
                    width="content",
                ):
                    if is_open:
                        expanded_folders.discard(folder_key)
                    else:
                        expanded_folders.add(folder_key)
                    st.rerun()
                if is_open:
                    _render_tree_node(child, folder_key, depth + 1)

            for rel_path in node["files"]:
                file_name = rel_path.rsplit("/", 1)[-1]
                icon = "☕" if rel_path.endswith(".java") else ("🐍" if rel_path.endswith(".py") else "📄")
                is_active = rel_path == focused_file
                if st.button(
                    f"{icon} {file_name}",
                    key=f"tree_btn_d{depth}__{rel_path}",
                    type="primary" if is_active else "tertiary",
                    width="content",
                ):
                    st.session_state["sl_focused_file"] = rel_path
                    st.session_state["sl_focused_line"] = None
                    st.rerun()

        with st.container(border=True, height=400, key="sl_tree_box", gap=None, horizontal_alignment="left"):
            root_open = "__root__" in expanded_folders
            root_arrow = "▾ 📦" if root_open else "▸ 📦"
            if st.button(
                f"{root_arrow} {project.name}",
                key="dir_btn_d0____root__",
                type="tertiary",
                width="content",
            ):
                if root_open:
                    expanded_folders.discard("__root__")
                else:
                    expanded_folders.add("__root__")
                st.rerun()
            if root_open:
                _render_tree_node(tree, depth=1)

    with col_viewer:
        font_size = int(st.session_state.get("sl_code_font_size", 14))
        head_col, zoom_out_col, zoom_val_col, zoom_in_col = st.columns([5.2, 0.9, 0.8, 0.9])
        with head_col:
            line_badge = f" · 🎯 Line {focused_line}" if focused_line else ""
            st.markdown(
                f"<div style='padding-top:4px;font-size:14px;'>"
                f"<strong>📄 Code Viewer</strong>{line_badge}<br>"
                f"<span style='color:#94a3b8;font-family:monospace;font-size:12px;'>{html.escape(focused_file)}</span>"
                f"</div>",
                unsafe_allow_html=True,
            )
        with zoom_out_col:
            if st.button("A-", key="sl_zoom_out", help="Zoom Out (smaller font)", disabled=(font_size <= 12), use_container_width=True):
                st.session_state["sl_code_font_size"] = max(12, font_size - 2)
                st.rerun()
        with zoom_val_col:
            st.markdown(f"<div style='text-align:center;padding-top:6px;font-size:13px;color:#94a3b8;'>{font_size}px</div>", unsafe_allow_html=True)
        with zoom_in_col:
            if st.button("A+", key="sl_zoom_in", help="Zoom In (larger font)", disabled=(font_size >= 22), use_container_width=True):
                st.session_state["sl_code_font_size"] = min(22, font_size + 2)
                st.rerun()

        try:
            file_content = read_repo_file(project, focused_file)
            if focused_line:
                lines = file_content.splitlines()
                if 1 <= focused_line <= len(lines):
                    st.warning(f"🎯 **Highlighted Finding — Line {focused_line}:** `{lines[focused_line - 1].strip()}`")
            viewer_html = _render_code_viewer_html(
                file_content,
                highlight_line=focused_line,
                font_size=font_size,
            )
            st.html(viewer_html)
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
    st.subheader("Static Security Scan")
    by_tool = Counter(item.tool for item in findings)
    by_severity = Counter(item.severity for item in findings)
    high_cnt = by_severity.get("HIGH", 0)
    med_cnt = by_severity.get("MEDIUM", 0)
    low_cnt = by_severity.get("LOW", 0)
    semgrep_cnt = by_tool.get("semgrep", 0)
    bandit_cnt = by_tool.get("bandit", 0)

    st.html(
        _render_kpi_cards_html([
            {
                "title": "Total findings",
                "value": str(len(findings)),
                "subtitle": "Raw static-analysis alerts",
            },
            {
                "title": "Semgrep*",
                "value": str(semgrep_cnt),
                "subtitle": "Pattern & CWE rules",
            },
            {
                "title": "Bandit",
                "value": str(bandit_cnt),
                "subtitle": "Python AST checks",
            },
            {
                "title": "High severity",
                "value": str(high_cnt),
                "subtitle": f"{med_cnt} medium · {low_cnt} low",
                "dot": "#cf5b56" if high_cnt else "#3f8f56",
            },
        ])
    )
    st.html(
        _render_breakdown_bar_html(
            "Severity distribution",
            f"{len(findings)} alert(s)",
            [
                ("High", high_cnt, "#cf5b56"),
                ("Medium", med_cnt, "#c48a34"),
                ("Low", low_cnt, "#6e7681"),
            ],
        )
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
    st.subheader("AI Triage & Vulnerability Dashboard")
    total_alerts = len(findings)
    filtered_pct = round((len(dismissed_list) / total_alerts) * 100) if total_alerts else 0
    st.html(
        _render_kpi_cards_html([
            {
                "title": "Confirmed",
                "value": str(len(strict_confirmed_list)),
                "subtitle": "Verified true positives",
                "dot": "#cf5b56",
            },
            {
                "title": "Uncertain",
                "value": str(len(uncertain_list)),
                "subtitle": "Retained conservatively",
                "dot": "#c48a34",
            },
            {
                "title": "Dismissed",
                "value": str(len(dismissed_list)),
                "subtitle": f"{filtered_pct}% false positives filtered",
                "dot": "#3f8f56",
            },
            {
                "title": "To remediate",
                "value": str(len(all_confirmed)),
                "subtitle": "Queued for patching",
                "dot": "#8b949e",
            },
        ])
    )
    st.html(
        _render_breakdown_bar_html(
            "Triage outcome",
            f"{total_alerts} scanned → {len(dismissed_list)} filtered ({filtered_pct}% reduction)",
            [
                ("Confirmed", len(strict_confirmed_list), "#cf5b56"),
                ("Uncertain", len(uncertain_list), "#c48a34"),
                ("Dismissed", len(dismissed_list), "#3f8f56"),
            ],
        )
    )

    tab_all, tab_conf, tab_unc, tab_dism = st.tabs([
        f"All findings ({len(findings)})",
        f"Confirmed ({len(strict_confirmed_list)})",
        f"Uncertain ({len(uncertain_list)})",
        f"Dismissed ({len(dismissed_list)})",
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
    st.subheader("Proposed Patches & Review")
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

            st.html(
                _render_kpi_cards_html([
                    {
                        "title": "Proposed patches",
                        "value": str(len(patches)),
                        "subtitle": "Files with generated fixes",
                    },
                    {
                        "title": "Pending review",
                        "value": str(pending_count),
                        "subtitle": "Awaiting decision",
                        "dot": "#c48a34",
                    },
                    {
                        "title": "Approved",
                        "value": str(approved_count),
                        "subtitle": "Ready for sandbox apply",
                        "dot": "#3f8f56",
                    },
                    {
                        "title": "Rejected",
                        "value": str(rejected_count),
                        "subtitle": "Excluded from sandbox",
                        "dot": "#cf5b56",
                    },
                ])
            )

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
        st.subheader("Post-Patch Security Rescan")
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

        st.subheader("Regression Tests")
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

        st.subheader("Final Security Verdict")
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
    st.info("Inspect files in the explorer above or click **🚀 Run Semgrep* Scan & AI Triage** to begin the security review.")
