"""Streamlit UI for SecureLens: GitHub Import, Semgrep*, Evidence-Grounded Triage, Code Explorer, & HITL Patching."""

from __future__ import annotations

import hashlib
import html
import re
import subprocess
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

st.set_page_config(
    page_title="SecureLens",
    page_icon="🔎",
    layout="wide",
    initial_sidebar_state="collapsed",
)

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
    padding-top: 3.95rem !important;
    padding-left: 0.75rem !important;
    padding-right: 1rem !important;
    padding-bottom: 2.2rem !important;
    max-width: 100% !important;
}}
section[data-testid="stSidebar"],
[data-testid="stSidebarCollapsedControl"],
[data-testid="stExpandSidebarButton"] {{
    display: none !important;
}}
header[data-testid="stHeader"] {{
    background: #161b22 !important;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
}}
header[data-testid="stHeader"]::after {{
    content: "🔎 SecureLens";
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: flex-start;
    padding-left: 18px;
    font-size: 15px;
    font-weight: 600;
    color: #f0f6fc;
    letter-spacing: 0.01em;
    pointer-events: none;
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
.st-key-sl_activity_rail {{
    background: #161b22 !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 8px !important;
    padding: 6px 2px !important;
    min-width: 46px !important;
}}
.st-key-sl_activity_rail [data-testid="stVerticalBlock"] {{
    gap: 4px !important;
}}
.st-key-sl_activity_rail button[data-testid^="stBaseButton"] {{
    min-height: 42px !important;
    padding: 6px 0 !important;
    border-radius: 6px !important;
    border: none !important;
    border-left: 2px solid transparent !important;
    background: transparent !important;
    color: #8b949e !important;
    box-shadow: none !important;
}}
.st-key-sl_activity_rail button[data-testid^="stBaseButton"]:hover {{
    background: rgba(255, 255, 255, 0.06) !important;
    color: #f0f6fc !important;
}}
.st-key-sl_activity_rail button[data-testid="stBaseButton-primary"] {{
    background: rgba(255, 255, 255, 0.08) !important;
    border-left: 2px solid #f0f6fc !important;
    color: #f0f6fc !important;
}}
.st-key-sl_drawer_panel {{
    background: #161b22 !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 8px !important;
    padding: 10px 10px !important;
}}
.st-key-sl_drawer_controls button[data-testid^="stBaseButton"] {{
    min-height: 26px !important;
    height: 26px !important;
    padding: 0 4px !important;
    border: none !important;
    background: transparent !important;
    color: #8b949e !important;
    box-shadow: none !important;
}}
.st-key-sl_drawer_controls button[data-testid^="stBaseButton"]:hover {{
    background: rgba(255, 255, 255, 0.08) !important;
    color: #f0f6fc !important;
}}
.st-key-sl_editor_tabs {{
    background: #161b22 !important;
    border: 1px solid rgba(255, 255, 255, 0.10) !important;
    border-bottom: none !important;
    border-radius: 8px 8px 0 0 !important;
    padding: 5px 8px 0 8px !important;
    gap: 2px !important;
    overflow-x: auto !important;
}}
.st-key-sl_editor_tabs button[data-testid^="stBaseButton"] {{
    min-height: 30px !important;
    height: 30px !important;
    padding: 2px 10px !important;
    font-size: 12.5px !important;
    border-radius: 6px 6px 0 0 !important;
    border: 1px solid transparent !important;
    border-bottom: none !important;
    background: transparent !important;
    color: #8b949e !important;
    box-shadow: none !important;
}}
.st-key-sl_editor_tabs button[data-testid^="stBaseButton"]:hover {{
    background: rgba(255, 255, 255, 0.05) !important;
    color: #e6edf3 !important;
}}
.st-key-sl_editor_tabs button[data-testid="stBaseButton-primary"] {{
    background: #0e1117 !important;
    border: 1px solid rgba(255, 255, 255, 0.10) !important;
    border-top: 2px solid #2f81f7 !important;
    border-bottom: none !important;
    color: #f0f6fc !important;
    font-weight: 600 !important;
}}
.st-key-sl_editor_tabs [class*="st-key-close_tab__"] button[data-testid^="stBaseButton"] {{
    padding: 2px 6px !important;
    font-size: 11px !important;
    color: #6e7681 !important;
    margin-right: 6px !important;
}}
.st-key-sl_editor_tabs [class*="st-key-close_tab__"] button[data-testid^="stBaseButton"]:hover {{
    color: #f85149 !important;
    background: rgba(248, 81, 73, 0.12) !important;
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
@media (min-width: 768px) {{
    .block-container {{
        padding-top: 3.75rem !important;
        padding-bottom: 0.35rem !important;
    }}
    [data-testid="stHorizontalBlock"]:has(.st-key-sl_activity_rail) {{
        align-items: stretch !important;
    }}
    [data-testid="stHorizontalBlock"]:has(.st-key-sl_activity_rail) > [data-testid="stColumn"]:not(:last-child) {{
        position: sticky !important;
        top: 3.75rem !important;
        height: calc(100vh - 4.25rem) !important;
        max-height: calc(100vh - 4.25rem) !important;
        overflow-y: auto !important;
        overflow-x: hidden !important;
    }}
    [data-testid="stHorizontalBlock"]:has(.st-key-sl_activity_rail) > [data-testid="stColumn"]:last-child {{
        height: calc(100vh - 4.25rem) !important;
        max-height: calc(100vh - 4.25rem) !important;
        overflow-y: auto !important;
        overflow-x: hidden !important;
        padding-right: 6px !important;
    }}
    .st-key-sl_activity_rail,
    .st-key-sl_drawer_panel {{
        min-height: calc(100vh - 4.35rem) !important;
        box-sizing: border-box !important;
    }}
    .st-key-sl_tree_box {{
        min-height: calc(100vh - 14.2rem) !important;
        height: calc(100vh - 14.2rem) !important;
    }}
}}
[data-testid="stHorizontalBlock"]:has(.st-key-sl_activity_rail) > [data-testid="stColumn"]:last-child h3 {{
    font-size: 1.05rem !important;
    margin-top: 0.2rem !important;
    margin-bottom: 0.25rem !important;
    padding: 0 !important;
}}
[data-testid="stHorizontalBlock"]:has(.st-key-sl_activity_rail) > [data-testid="stColumn"]:last-child hr {{
    margin: 0.6rem 0 !important;
}}
[class*="st-key-err_pick_"] button[data-testid^="stBaseButton"],
[class*="st-key-patch_pick_"] button[data-testid^="stBaseButton"] {{
    justify-content: flex-start !important;
    text-align: left !important;
    padding: 6px 12px !important;
    min-height: 36px !important;
    font-size: 13px !important;
    background: rgba(255, 255, 255, 0.03) !important;
    border: 1px solid rgba(255, 255, 255, 0.10) !important;
    color: #e6edf3 !important;
}}
[class*="st-key-err_pick_"] button[data-testid^="stBaseButton"] p,
[class*="st-key-patch_pick_"] button[data-testid^="stBaseButton"] p {{
    margin: 0 !important;
    text-align: left !important;
}}
[class*="st-key-err_pick_"] button[data-testid^="stBaseButton"]:hover,
[class*="st-key-patch_pick_"] button[data-testid^="stBaseButton"]:hover {{
    background: rgba(255, 255, 255, 0.07) !important;
}}
[class*="st-key-err_pick_"] button[data-testid="stBaseButton-primary"],
[class*="st-key-patch_pick_"] button[data-testid="stBaseButton-primary"] {{
    background: rgba(47, 129, 247, 0.14) !important;
    border: 1px solid rgba(47, 129, 247, 0.45) !important;
    color: #f0f6fc !important;
}}
[class*="st-key-sl_err_card_open_"],
[class*="st-key-sl_patch_card_open_"] {{
    background: #161b22 !important;
    border: 1px solid rgba(88, 166, 255, 0.35) !important;
    border-radius: 8px !important;
    padding: 10px 14px 14px 14px !important;
    margin: 2px 0 8px 0 !important;
}}
[class*="st-key-sl_err_card_open_"] [class*="st-key-err_pick_"] button[data-testid="stBaseButton-primary"],
[class*="st-key-sl_patch_card_open_"] [class*="st-key-patch_pick_"] button[data-testid="stBaseButton-primary"] {{
    background: transparent !important;
    border: none !important;
    padding: 2px 4px !important;
    min-height: 30px !important;
    color: #f0f6fc !important;
    font-weight: 600 !important;
}}
[class*="st-key-sl_err_card_open_"] [class*="st-key-err_pick_"] button[data-testid="stBaseButton-primary"]:hover,
[class*="st-key-sl_patch_card_open_"] [class*="st-key-patch_pick_"] button[data-testid="stBaseButton-primary"]:hover {{
    background: rgba(255, 255, 255, 0.05) !important;
}}
[class*="st-key-goto_hl_"] button[data-testid^="stBaseButton"],
[class*="st-key-goto_patch_hl_"] button[data-testid^="stBaseButton"] {{
    justify-content: center !important;
    text-align: center !important;
    background: rgba(56, 139, 253, 0.10) !important;
    border: 1px solid rgba(88, 166, 255, 0.35) !important;
    color: #79c0ff !important;
    white-space: nowrap !important;
}}
[class*="st-key-goto_hl_"] button[data-testid^="stBaseButton"] p,
[class*="st-key-goto_patch_hl_"] button[data-testid^="stBaseButton"] p {{
    text-align: center !important;
    font-weight: 500 !important;
}}
[class*="st-key-goto_hl_"] button[data-testid^="stBaseButton"]:hover,
[class*="st-key-goto_patch_hl_"] button[data-testid^="stBaseButton"]:hover {{
    background: rgba(56, 139, 253, 0.20) !important;
    border-color: rgba(88, 166, 255, 0.65) !important;
    color: #a5d6ff !important;
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
    highlight_lines: dict[int, str] | None = None,
    font_size: int = 14,
    max_height: int = 540,
    rounded_top: bool = False,
    viewer_id: str | None = None,
) -> str:
    """Render line-numbered code HTML with zoomable font size and multi-finding + active line highlighting."""
    clamped_size = max(12, min(22, int(font_size)))
    lines = content.splitlines() or [""]
    rows: list[str] = []
    passive_styles = {
        "confirmed": ("background:rgba(207,91,86,0.16);border-left:4px solid #cf5b56;", "color:#f87171;font-weight:600;"),
        "uncertain": ("background:rgba(196,138,52,0.15);border-left:4px solid #c48a34;", "color:#fbbf24;font-weight:600;"),
        "dismissed": ("background:rgba(63,143,86,0.12);border-left:4px solid #3f8f56;", "color:#4ade80;font-weight:600;"),
    }
    safe_vid = html.escape(viewer_id) if viewer_id else ""
    for idx, text in enumerate(lines, start=1):
        is_hit = highlight_line == idx
        passive_kind = (highlight_lines or {}).get(idx)
        row_id_attr = f' id="{safe_vid}-hit"' if (is_hit and safe_vid) else ""
        if is_hit:
            row_style = (
                "display:flex;align-items:baseline;padding:2px 12px;"
                "background:linear-gradient(90deg,rgba(239,68,68,0.34) 0%,rgba(245,158,11,0.22) 100%);"
                "border-left:4px solid #ef4444;color:#fff7ed;font-weight:600;"
            )
            gutter_style = "min-width:4.4em;text-align:right;padding-right:12px;user-select:none;flex-shrink:0;color:#fbbf24;font-weight:700;"
            marker = f"🎯 {idx}"
        elif passive_kind in passive_styles:
            bg, gcol = passive_styles[passive_kind]
            row_style = f"display:flex;align-items:baseline;padding:1px 12px;{bg}"
            gutter_style = f"min-width:4.4em;text-align:right;padding-right:12px;user-select:none;flex-shrink:0;{gcol}"
            marker = f"● {idx}"
        else:
            row_style = "display:flex;align-items:baseline;padding:1px 12px;border-left:4px solid transparent;"
            gutter_style = "min-width:4.4em;text-align:right;padding-right:12px;user-select:none;flex-shrink:0;color:#64748b;"
            marker = str(idx)
        escaped_line = html.escape(text) if text else "&nbsp;"
        rows.append(
            f'<div{row_id_attr} style="{row_style}">'
            f'<span style="{gutter_style}">{marker}</span>'
            f'<span style="white-space:pre;">{escaped_line}</span>'
            f"</div>"
        )
    radius = "8px" if rounded_top else "0 0 8px 8px"
    top_border = "border:1px solid rgba(255,255,255,0.10);" if rounded_top else "border:1px solid rgba(255,255,255,0.10);border-top:none;"
    container_id_attr = f' id="{safe_vid}"' if safe_vid else ""
    container_style = (
        f"position:relative;background:#161b22;color:#e6edf3;{top_border}border-radius:{radius};"
        f"padding:10px 0;max-height:{max_height}px;overflow:auto;"
        "font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;"
        f"font-size:{clamped_size}px;line-height:1.55;"
    )
    return f'<div{container_id_attr} style="{container_style}">{"".join(rows)}</div>'


def _render_diff_viewer_html(
    diff_text: str,
    *,
    highlight_line: int | None = None,
    font_size: int = 14,
    max_height: int = 420,
    viewer_id: str | None = None,
) -> str:
    """Render unified diff HTML with zoomable font size and active line-hit highlighting."""
    clamped_size = max(12, min(22, int(font_size)))
    lines = diff_text.splitlines() if diff_text.strip() else ["(No source differences generated)"]
    rows: list[str] = []
    safe_vid = html.escape(viewer_id) if viewer_id else ""
    old_ln = 0
    new_ln = 0
    hit_emitted = False
    hunk_re = re.compile(r"^@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@")

    for text in lines:
        m = hunk_re.match(text)
        row_id_attr = ""
        if m:
            old_ln = int(m.group(1))
            new_ln = int(m.group(2))
            row_style = "display:flex;align-items:baseline;padding:2px 12px;background:rgba(56,139,253,0.12);border-left:4px solid #388bfd;color:#79c0ff;"
            gutter = "@@"
        elif text.startswith("--- ") or text.startswith("+++ "):
            row_style = "display:flex;align-items:baseline;padding:1px 12px;border-left:4px solid transparent;color:#8b949e;font-weight:600;"
            gutter = " "
        elif text.startswith("-"):
            line_no = old_ln
            old_ln += 1
            is_hit = highlight_line is not None and line_no == highlight_line
            if is_hit and safe_vid and not hit_emitted:
                row_id_attr = f' id="{safe_vid}-hit"'
                hit_emitted = True
            if is_hit:
                row_style = "display:flex;align-items:baseline;padding:2px 12px;background:rgba(248,81,73,0.30);border-left:4px solid #ef4444;color:#ffdcd7;font-weight:600;"
                gutter = f"🎯 -{line_no}"
            else:
                row_style = "display:flex;align-items:baseline;padding:1px 12px;background:rgba(248,81,73,0.12);border-left:4px solid #f85149;color:#ffa198;"
                gutter = f"-{line_no}" if line_no > 0 else "-"
        elif text.startswith("+"):
            line_no = new_ln
            new_ln += 1
            is_hit = highlight_line is not None and line_no == highlight_line
            if is_hit and safe_vid and not hit_emitted:
                row_id_attr = f' id="{safe_vid}-hit"'
                hit_emitted = True
            if is_hit:
                row_style = "display:flex;align-items:baseline;padding:2px 12px;background:rgba(63,185,80,0.28);border-left:4px solid #fbbf24;color:#dcfce7;font-weight:600;"
                gutter = f"🎯 +{line_no}"
            else:
                row_style = "display:flex;align-items:baseline;padding:1px 12px;background:rgba(63,185,80,0.12);border-left:4px solid #3fb950;color:#7ee787;"
                gutter = f"+{line_no}" if line_no > 0 else "+"
        else:
            line_no = old_ln if old_ln > 0 else new_ln
            if old_ln > 0:
                old_ln += 1
            if new_ln > 0:
                new_ln += 1
            is_hit = highlight_line is not None and line_no == highlight_line
            if is_hit and safe_vid and not hit_emitted:
                row_id_attr = f' id="{safe_vid}-hit"'
                hit_emitted = True
            if is_hit:
                row_style = "display:flex;align-items:baseline;padding:2px 12px;background:rgba(245,158,11,0.20);border-left:4px solid #fbbf24;color:#fff7ed;font-weight:600;"
                gutter = f"🎯 {line_no}"
            else:
                row_style = "display:flex;align-items:baseline;padding:1px 12px;border-left:4px solid transparent;color:#c9d1d9;"
                gutter = str(line_no) if line_no > 0 else ""

        escaped_line = html.escape(text) if text else "&nbsp;"
        rows.append(
            f'<div{row_id_attr} style="{row_style}">'
            f'<span style="min-width:4.8em;text-align:right;padding-right:12px;user-select:none;flex-shrink:0;opacity:0.85;">{gutter}</span>'
            f'<span style="white-space:pre;">{escaped_line}</span>'
            f"</div>"
        )

    container_id_attr = f' id="{safe_vid}"' if safe_vid else ""
    container_style = (
        "position:relative;background:#161b22;color:#e6edf3;border:1px solid rgba(255,255,255,0.10);"
        f"border-radius:8px;padding:10px 0;max-height:{max_height}px;overflow:auto;"
        "font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;"
        f"font-size:{clamped_size}px;line-height:1.55;"
    )
    return f'<div{container_id_attr} style="{container_style}">{"".join(rows)}</div>'


def _emit_scroll_to_highlight_script(
    viewer_ids: list[str],
    *,
    nonce: int,
    scroll_page: bool,
) -> None:
    """Emit a DOM script that scrolls the visible code/diff container (and page when requested) to `-hit`."""
    import json

    ids_json = json.dumps(viewer_ids)
    outer_flag = "true" if scroll_page else "false"
    st.html(
        f"""<script>
// scroll-nonce: {nonce}
(function() {{
  const ids = {ids_json};
  function jumpToHit() {{
    let targetBox = null;
    let targetHit = null;
    for (const vid of ids) {{
      const box = document.getElementById(vid);
      const hit = document.getElementById(vid + "-hit");
      if (box && hit) {{
        if (box.offsetParent !== null) {{
          targetBox = box;
          targetHit = hit;
          break;
        }}
        if (!targetBox) {{
          targetBox = box;
          targetHit = hit;
        }}
      }}
    }}
    if (!targetBox || !targetHit) return;
    const targetTop = targetHit.offsetTop - Math.max(0, (targetBox.clientHeight - targetHit.offsetHeight) / 2);
    targetBox.scrollTop = Math.max(0, targetTop);
    if ({outer_flag}) {{
      targetHit.scrollIntoView({{ behavior: "smooth", block: "center" }});
    }}
  }}
  requestAnimationFrame(() => setTimeout(jumpToHit, 60));
}})();
</script>""",
        unsafe_allow_javascript=True,
    )


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
    """Render a compact, neutral row of security KPI cards with subtle status dots."""
    tiles: list[str] = []
    for card in cards:
        dot_color = html.escape(card.get("dot", "#8b949e"))
        title = html.escape(card["title"])
        value = html.escape(str(card["value"]))
        subtitle = html.escape(card["subtitle"])
        dot_html = (
            f'<span style="width:6px;height:6px;border-radius:50%;background:{dot_color};'
            f'display:inline-block;margin-right:6px;"></span>'
            if card.get("dot")
            else ""
        )
        tiles.append(
            '<div style="background:rgba(255,255,255,0.025);border:1px solid rgba(255,255,255,0.09);'
            'border-radius:6px;padding:8px 12px;">'
            '<div style="display:flex;align-items:baseline;justify-content:space-between;gap:8px;">'
            f'<span style="display:inline-flex;align-items:center;font-size:12px;font-weight:500;color:#8b949e;">'
            f'{dot_html}<span>{title}</span></span>'
            f'<span style="font-size:18px;font-weight:700;color:#f0f6fc;line-height:1.1;'
            f'font-variant-numeric:tabular-nums;">{value}</span>'
            "</div>"
            f'<div style="font-size:11px;color:#6e7681;margin-top:2px;">{subtitle}</div>'
            "</div>"
        )
    return (
        '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));'
        'gap:8px;margin:2px 0 6px 0;">'
        + "".join(tiles)
        + "</div>"
    )


def _render_breakdown_bar_html(
    label: str,
    summary_text: str,
    segments: list[tuple[str, int, str]],
) -> str:
    """Render a compact segmented breakdown strip."""
    total = sum(count for _, count, _ in segments)
    legend = "".join(
        f'<span style="display:inline-flex;align-items:center;gap:5px;font-size:11.5px;color:#8b949e;">'
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
        'border-radius:6px;padding:7px 12px;margin:0 0 8px 0;">'
        '<div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:8px;margin-bottom:5px;">'
        f'<div style="font-size:12px;font-weight:500;color:#c9d1d9;">{html.escape(label)}'
        f' <span style="font-weight:400;color:#6e7681;margin-left:6px;">{html.escape(summary_text)}</span></div>'
        f'<div style="display:flex;flex-wrap:wrap;gap:12px;">{legend}</div>'
        "</div>"
        '<div style="display:flex;height:3px;border-radius:999px;overflow:hidden;background:rgba(255,255,255,0.06);">'
        f"{bar_parts}"
        "</div>"
        "</div>"
    )


def _pick_local_folder(initial_dir: str | None = None) -> str | None:
    """Open a native OS folder picker dialog in a subprocess and return the selected directory path."""
    start = Path(initial_dir).expanduser() if initial_dir else Path.home()
    if not start.is_dir():
        start = Path.home()
    if sys.platform == "darwin":
        escaped = str(start).replace("\\", "\\\\").replace('"', '\\"')
        script = (
            f'POSIX path of (choose folder with prompt "Select project folder" '
            f'default location (POSIX file "{escaped}"))'
        )
        try:
            res = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=120, check=False)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip().rstrip("/") or "/"
        except (OSError, subprocess.SubprocessError):
            return None
        return None
    code = (
        "import sys, tkinter as tk; from tkinter import filedialog; "
        "r = tk.Tk(); r.withdraw(); r.attributes('-topmost', True); "
        "p = filedialog.askdirectory(initialdir=sys.argv[1], title='Select project folder'); "
        "print(p or '')"
    )
    try:
        res = subprocess.run([sys.executable, "-c", code, str(start)], capture_output=True, text=True, timeout=120, check=False)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return None


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

def _open_file_in_tab(rel_path: str, *, line: int | None = None) -> None:
    """Open a file in the main VS Code-style editor tab strip and focus it."""
    tabs: list[str] = list(st.session_state.get("sl_open_tabs", []))
    if rel_path not in tabs:
        tabs.append(rel_path)
    st.session_state["sl_open_tabs"] = tabs
    st.session_state["sl_focused_file"] = rel_path
    st.session_state["sl_focused_line"] = line


def _get_state(name: str, default):
    return st.session_state.get(f"sl_{name}", default)


def _store(name: str, value) -> None:
    st.session_state[f"sl_{name}"] = value


def _current_report(project: Path) -> PipelineReport:
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


def _render_security_pipeline(project: Path, llm_client: LLMClient, triage_key: str) -> None:
    """Render the static scan, AI triage, patch review, rescan, regression, and verdict stages."""
    st.divider()
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

        status_filter = st.radio(
            "Filter findings",
            [
                f"All ({len(findings)})",
                f"Confirmed ({len(strict_confirmed_list)})",
                f"Uncertain ({len(uncertain_list)})",
                f"Dismissed ({len(dismissed_list)})",
            ],
            horizontal=True,
            key="sl_dash_filter",
            label_visibility="collapsed",
        )
        if status_filter.startswith("Confirmed"):
            filtered_findings = strict_confirmed_list
        elif status_filter.startswith("Uncertain"):
            filtered_findings = uncertain_list
        elif status_filter.startswith("Dismissed"):
            filtered_findings = dismissed_list
        else:
            filtered_findings = findings

        findings_by_file: dict[str, list[Finding]] = {}
        for item in filtered_findings:
            findings_by_file.setdefault(item.file, []).append(item)

        if not findings_by_file:
            st.info("No findings in this category.")
        else:
            file_keys = sorted(findings_by_file.keys())
            file_tab_labels = [f"{fpath.rsplit('/', 1)[-1]} ({len(findings_by_file[fpath])})" for fpath in file_keys]
            file_tabs = st.tabs(file_tab_labels)

            for tab_widget, fpath in zip(file_tabs, file_keys):
                with tab_widget:
                    file_findings = sorted(findings_by_file[fpath], key=lambda item: item.line)
                    sel_state_key = f"sl_dash_sel_{fpath}"
                    valid_ids = [item.id for item in file_findings]
                    selected_id = st.session_state.get(sel_state_key)
                    if selected_id not in valid_ids:
                        selected_id = None
                        st.session_state[sel_state_key] = None

                    selected_finding = (
                        next((item for item in file_findings if item.id == selected_id), None)
                        if selected_id
                        else None
                    )
                    line_map: dict[int, str] = {}
                    for item in file_findings:
                        v = verdicts_by_id.get(item.id)
                        v_status = v.status if v else "confirmed"
                        if item.line not in line_map or v_status == "confirmed":
                            line_map[item.line] = v_status

                    viewer_id = "sl-dash-code-" + hashlib.sha1(fpath.encode("utf-8")).hexdigest()[:10]
                    try:
                        full_source = read_repo_file(project, fpath)
                        dash_font = int(st.session_state.get("sl_code_font_size", 14))
                        st.html(
                            _render_code_viewer_html(
                                full_source,
                                highlight_line=(selected_finding.line if selected_finding else None),
                                highlight_lines=line_map,
                                font_size=dash_font,
                                max_height=420,
                                rounded_top=True,
                                viewer_id=viewer_id,
                            )
                        )
                    except Exception as exc:
                        st.error(f"Could not read `{fpath}`: {exc}")

                    scroll_mode = st.session_state.pop(f"sl_dash_scroll_mode_{fpath}", None)
                    if selected_finding is not None and scroll_mode in ("box", "page"):
                        _emit_scroll_to_highlight_script(
                            [viewer_id],
                            nonce=int(st.session_state.get(f"sl_dash_scroll_nonce_{fpath}", 0)),
                            scroll_page=(scroll_mode == "page"),
                        )

                    with st.container(key=f"sl_err_list_{fpath}"):
                        for idx, finding in enumerate(file_findings):
                            err_num = idx + 1
                            verdict = verdicts_by_id.get(finding.id)
                            status_tag = verdict.status.upper() if verdict else "UNASSESSED"
                            dot = "🔴" if status_tag == "CONFIRMED" else ("🟡" if status_tag == "UNCERTAIN" else "🟢")
                            cwe_short = (finding.cwe or "Unmapped").split(":", 1)[0].strip()
                            is_selected = selected_finding is not None and finding.id == selected_finding.id
                            caret = "▾" if is_selected else "▸"
                            btn_label = (
                                f"{caret} Error {err_num} · Line {finding.line}  ·  {dot} {status_tag}  ·  "
                                f"{finding.severity}  ·  {cwe_short}  ·  {finding.rule_id}"
                            )
                            def _render_finding_row() -> None:
                                col_drop, col_goto = st.columns([0.80, 0.20], gap="small")
                                with col_drop:
                                    if st.button(
                                        btn_label,
                                        key=f"err_pick_{fpath}_{finding.id}_{idx}",
                                        type="primary" if is_selected else "secondary",
                                        use_container_width=True,
                                    ):
                                        if is_selected:
                                            st.session_state[sel_state_key] = None
                                        else:
                                            st.session_state[sel_state_key] = finding.id
                                            st.session_state[f"sl_dash_scroll_mode_{fpath}"] = "box"
                                            st.session_state[f"sl_dash_scroll_nonce_{fpath}"] = (
                                                st.session_state.get(f"sl_dash_scroll_nonce_{fpath}", 0) + 1
                                            )
                                        st.rerun()
                                with col_goto:
                                    if st.button(
                                        f"🎯 Go to Line {finding.line}",
                                        key=f"goto_hl_{fpath}_{finding.id}_{idx}",
                                        use_container_width=True,
                                    ):
                                        st.session_state[sel_state_key] = finding.id
                                        st.session_state[f"sl_dash_scroll_mode_{fpath}"] = "page"
                                        st.session_state[f"sl_dash_scroll_nonce_{fpath}"] = (
                                            st.session_state.get(f"sl_dash_scroll_nonce_{fpath}", 0) + 1
                                        )
                                        st.rerun()

                            if is_selected:
                                status_colors = {
                                    "CONFIRMED": ("#f87171", "rgba(248,113,113,0.12)"),
                                    "UNCERTAIN": ("#fbbf24", "rgba(251,191,36,0.12)"),
                                    "DISMISSED": ("#4ade80", "rgba(74,222,128,0.12)"),
                                }
                                fg_col, bg_col = status_colors.get(status_tag, ("#94a3b8", "rgba(148,163,184,0.12)"))
                                cwe_full = html.escape(finding.cwe or "CWE-Unmapped")
                                msg_html = html.escape(finding.message)
                                reason_html = html.escape(verdict.reason) if verdict else "Not triaged yet."
                                conf_html = f"{verdict.confidence:.2f}" if verdict else "—"
                                ev_line = (verdict.evidence_line if verdict and verdict.evidence_line else finding.line)
                                ev_snip = html.escape((verdict.evidence_snippet if verdict and verdict.evidence_snippet else finding.snippet).strip())
                                verified_txt = (
                                    "Verified in file"
                                    if (verdict and verdict.grounding_verified)
                                    else "Unverified / conservative"
                                )
                                with st.container(key=f"sl_err_card_open_{fpath}_{idx}"):
                                    _render_finding_row()
                                    st.html(
                                        f'<div style="border-top:1px solid rgba(255,255,255,0.08);'
                                        f'border-left:3px solid {fg_col};padding:10px 0 2px 12px;margin-top:4px;">'
                                        f'<div style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:8px;">'
                                        f'<span style="background:{bg_col};color:{fg_col};padding:2px 8px;border-radius:999px;font-size:11.5px;font-weight:600;">{status_tag} ({conf_html})</span>'
                                        f'<span style="color:#8b949e;font-size:12px;">{html.escape(finding.severity)} · {cwe_full} · {verified_txt}</span>'
                                        f'</div>'
                                        f'<div style="font-size:13px;color:#e6edf3;margin-bottom:6px;"><strong style="color:#8b949e;">Issue:</strong> {msg_html}</div>'
                                        f'<div style="font-size:13px;color:#c9d1d9;margin-bottom:6px;"><strong style="color:#8b949e;">AI Reason:</strong> {reason_html}</div>'
                                        f'<div style="font-size:12px;color:#8b949e;"><strong style="color:#8b949e;">Line {ev_line}:</strong> '
                                        f'<code style="background:#0d1117;color:#e6edf3;padding:2px 6px;border-radius:4px;">{ev_snip}</code></div>'
                                        f'</div>'
                                    )
                            else:
                                _render_finding_row()

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
                        for p_idx, p in enumerate(patches):
                            p.status = "approved"
                            st.session_state[f"sl_patch_err_decisions_{p_idx}_{p.file}"] = {
                                fid: "approved" for fid in p.addressed_finding_ids
                            }
                        _store("proposed_patches", proposed_state)
                        st.rerun()
                    if b_col2.button("Reject all patches"):
                        for p_idx, p in enumerate(patches):
                            p.status = "rejected"
                            st.session_state[f"sl_patch_err_decisions_{p_idx}_{p.file}"] = {
                                fid: "rejected" for fid in p.addressed_finding_ids
                            }
                        _store("proposed_patches", proposed_state)
                        st.rerun()

                findings_by_id = {f.id: f for f in findings}
                patch_tab_labels = [
                    (
                        f"{'⏳' if p.status == 'pending' else ('✅' if p.status == 'approved' else '❌')} "
                        f"{p.file.rsplit('/', 1)[-1]} ({len([fid for fid in p.addressed_finding_ids if fid in findings_by_id]) or 1})"
                    )
                    for p in patches
                ]
                patch_tabs = st.tabs(patch_tab_labels)
                patch_font = int(st.session_state.get("sl_code_font_size", 14))
                patch_colors = {
                    "PENDING": ("#fbbf24", "rgba(251,191,36,0.12)"),
                    "APPROVED": ("#4ade80", "rgba(74,222,128,0.12)"),
                    "REJECTED": ("#f87171", "rgba(248,113,113,0.12)"),
                }

                for p_tab, (idx, patch) in zip(patch_tabs, enumerate(patches)):
                    with p_tab:
                        status_label = patch.status.upper()
                        patch_dot = "🟡" if patch.status == "pending" else ("🟢" if patch.status == "approved" else "🔴")
                        addressed = sorted(
                            [findings_by_id[fid] for fid in patch.addressed_finding_ids if fid in findings_by_id],
                            key=lambda item: item.line,
                        )
                        patch_sel_key = f"sl_patch_sel_{idx}_{patch.file}"
                        err_dec_key = f"sl_patch_err_decisions_{idx}_{patch.file}"
                        err_decisions: dict[str, str] = st.session_state.setdefault(err_dec_key, {})
                        valid_patch_ids = [item.id for item in addressed] if addressed else ["__summary__"]
                        sel_patch_id = st.session_state.get(patch_sel_key)
                        if sel_patch_id not in valid_patch_ids:
                            sel_patch_id = None
                            st.session_state[patch_sel_key] = None

                        selected_addr = (
                            next((item for item in addressed if item.id == sel_patch_id), None)
                            if sel_patch_id and addressed
                            else None
                        )
                        orig_line_map = {item.line: "confirmed" for item in addressed}
                        prop_line_map = {item.line: "dismissed" for item in addressed}
                        p_hash = hashlib.sha1(f"{idx}:{patch.file}".encode("utf-8")).hexdigest()[:10]
                        diff_vid = f"sl-patch-diff-{p_hash}"
                        orig_vid = f"sl-patch-orig-{p_hash}"
                        prop_vid = f"sl-patch-prop-{p_hash}"

                        diff_tab, before_tab, after_tab = st.tabs(["Unified Diff", "Original (Before)", "Proposed (After)"])
                        with diff_tab:
                            st.html(
                                _render_diff_viewer_html(
                                    patch.diff or "(No source differences generated)",
                                    highlight_line=(selected_addr.line if selected_addr else None),
                                    font_size=patch_font,
                                    max_height=420,
                                    viewer_id=diff_vid,
                                )
                            )
                        with before_tab:
                            st.html(
                                _render_code_viewer_html(
                                    patch.original_code,
                                    highlight_line=(selected_addr.line if selected_addr else None),
                                    highlight_lines=orig_line_map,
                                    font_size=patch_font,
                                    max_height=420,
                                    rounded_top=True,
                                    viewer_id=orig_vid,
                                )
                            )
                        with after_tab:
                            st.html(
                                _render_code_viewer_html(
                                    patch.patched_code,
                                    highlight_line=(selected_addr.line if selected_addr else None),
                                    highlight_lines=prop_line_map,
                                    font_size=patch_font,
                                    max_height=420,
                                    rounded_top=True,
                                    viewer_id=prop_vid,
                                )
                            )

                        p_scroll_mode = st.session_state.pop(f"sl_patch_scroll_mode_{idx}_{patch.file}", None)
                        if selected_addr is not None and p_scroll_mode in ("box", "page"):
                            _emit_scroll_to_highlight_script(
                                [diff_vid, orig_vid, prop_vid],
                                nonce=int(st.session_state.get(f"sl_patch_scroll_nonce_{idx}_{patch.file}", 0)),
                                scroll_page=(p_scroll_mode == "page"),
                            )

                        def _apply_err_decision(target_id: str, decision: str) -> None:
                            err_decisions[target_id] = decision
                            all_decs = [err_decisions.get(x.id, patch.status) for x in addressed]
                            if not all_decs:
                                patch.status = decision
                            elif any(d == "pending" for d in all_decs):
                                patch.status = "pending"
                            elif any(d == "approved" for d in all_decs):
                                patch.status = "approved"
                            else:
                                patch.status = "rejected"
                            _store("proposed_patches", proposed_state)

                        with st.container(key=f"sl_patch_list_{idx}_{patch.file}"):
                            if addressed:
                                for f_idx, item in enumerate(addressed):
                                    err_num = f_idx + 1
                                    item_status = err_decisions.get(item.id, patch.status)
                                    item_label = item_status.upper()
                                    item_dot = "🟡" if item_status == "pending" else ("🟢" if item_status == "approved" else "🔴")
                                    i_fg, i_bg = patch_colors.get(item_label, ("#94a3b8", "rgba(148,163,184,0.12)"))
                                    cwe_short = (item.cwe or "Unmapped").split(":", 1)[0].strip()
                                    is_sel = selected_addr is not None and item.id == selected_addr.id
                                    caret = "▾" if is_sel else "▸"
                                    row_label = (
                                        f"{caret} Error {err_num} · Line {item.line}  ·  {item_dot} {item_label}  ·  "
                                        f"{item.severity}  ·  {cwe_short}  ·  {item.rule_id}"
                                    )
                                    def _render_patch_row() -> None:
                                        col_drop, col_goto = st.columns([0.80, 0.20], gap="small")
                                        with col_drop:
                                            if st.button(
                                                row_label,
                                                key=f"patch_pick_{idx}_{patch.file}_{item.id}_{f_idx}",
                                                type="primary" if is_sel else "secondary",
                                                use_container_width=True,
                                            ):
                                                if is_sel:
                                                    st.session_state[patch_sel_key] = None
                                                else:
                                                    st.session_state[patch_sel_key] = item.id
                                                    st.session_state[f"sl_patch_scroll_mode_{idx}_{patch.file}"] = "box"
                                                    st.session_state[f"sl_patch_scroll_nonce_{idx}_{patch.file}"] = (
                                                        st.session_state.get(f"sl_patch_scroll_nonce_{idx}_{patch.file}", 0) + 1
                                                    )
                                                st.rerun()
                                        with col_goto:
                                            if st.button(
                                                f"🎯 Go to Line {item.line}",
                                                key=f"goto_patch_hl_{idx}_{patch.file}_{item.id}_{f_idx}",
                                                use_container_width=True,
                                            ):
                                                st.session_state[patch_sel_key] = item.id
                                                st.session_state[f"sl_patch_scroll_mode_{idx}_{patch.file}"] = "page"
                                                st.session_state[f"sl_patch_scroll_nonce_{idx}_{patch.file}"] = (
                                                    st.session_state.get(f"sl_patch_scroll_nonce_{idx}_{patch.file}", 0) + 1
                                                )
                                                st.rerun()

                                    if is_sel:
                                        cwe_full = html.escape(item.cwe or "CWE-Unmapped")
                                        msg_html = html.escape(item.message)
                                        exp_html = html.escape(patch.explanation)
                                        snip_html = html.escape(item.snippet.strip())
                                        with st.container(key=f"sl_patch_card_open_{idx}_{patch.file}_{f_idx}"):
                                            _render_patch_row()
                                            st.html(
                                                f'<div style="border-top:1px solid rgba(255,255,255,0.08);'
                                                f'border-left:3px solid {i_fg};padding:10px 0 8px 12px;margin-top:4px;">'
                                                f'<div style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:8px;">'
                                                f'<span style="color:#e6edf3;font-size:12.5px;font-weight:700;">Error {err_num} · Line {item.line}</span>'
                                                f'<span style="background:{i_bg};color:{i_fg};padding:2px 8px;border-radius:999px;font-size:11.5px;font-weight:600;">{item_label}</span>'
                                                f'<span style="color:#8b949e;font-size:12px;">{html.escape(item.severity)} · {cwe_full}</span>'
                                                f'</div>'
                                                f'<div style="font-size:13px;color:#e6edf3;margin-bottom:6px;"><strong style="color:#8b949e;">Issue:</strong> {msg_html}</div>'
                                                f'<div style="font-size:13px;color:#c9d1d9;margin-bottom:6px;"><strong style="color:#8b949e;">AI Fix:</strong> {exp_html}</div>'
                                                f'<div style="font-size:12px;color:#8b949e;"><strong style="color:#8b949e;">Line {item.line}:</strong> '
                                                f'<code style="background:#0d1117;color:#e6edf3;padding:2px 6px;border-radius:4px;">{snip_html}</code></div>'
                                                f'</div>'
                                            )
                                            if fixes_state is None:
                                                c_app, c_rej, c_pen = st.columns(3)
                                                if c_app.button(
                                                    "✅ Approve",
                                                    key=f"btn_app_{idx}_{patch.file}_{item.id}_{f_idx}",
                                                    disabled=(item_status == "approved"),
                                                    use_container_width=True,
                                                ):
                                                    _apply_err_decision(item.id, "approved")
                                                    st.rerun()
                                                if c_rej.button(
                                                    "❌ Reject",
                                                    key=f"btn_rej_{idx}_{patch.file}_{item.id}_{f_idx}",
                                                    disabled=(item_status == "rejected"),
                                                    use_container_width=True,
                                                ):
                                                    _apply_err_decision(item.id, "rejected")
                                                    st.rerun()
                                                if c_pen.button(
                                                    "⏳ Mark Pending",
                                                    key=f"btn_pen_{idx}_{patch.file}_{item.id}_{f_idx}",
                                                    disabled=(item_status == "pending"),
                                                    use_container_width=True,
                                                ):
                                                    _apply_err_decision(item.id, "pending")
                                                    st.rerun()
                                            else:
                                                st.caption(f"Review status is locked as **{item_label}** during isolated sandbox validation.")
                                    else:
                                        _render_patch_row()
                            else:
                                p_fg, p_bg = patch_colors.get(status_label, ("#94a3b8", "rgba(148,163,184,0.12)"))
                                is_sum_sel = sel_patch_id == "__summary__"
                                sum_caret = "▾" if is_sum_sel else "▸"

                                def _render_summary_row() -> None:
                                    if st.button(
                                        f"{sum_caret} Patch 1 · {patch.file}  ·  {patch_dot} {status_label}",
                                        key=f"patch_pick_{idx}_{patch.file}_summary",
                                        type="primary" if is_sum_sel else "secondary",
                                        use_container_width=True,
                                    ):
                                        st.session_state[patch_sel_key] = None if is_sum_sel else "__summary__"
                                        st.rerun()

                                if is_sum_sel:
                                    with st.container(key=f"sl_patch_card_open_{idx}_{patch.file}_summary"):
                                        _render_summary_row()
                                        st.html(
                                            f'<div style="border-top:1px solid rgba(255,255,255,0.08);'
                                            f'border-left:3px solid {p_fg};padding:10px 0 8px 12px;margin-top:4px;">'
                                            f'<div style="font-size:13px;color:#c9d1d9;"><strong style="color:#8b949e;">AI Fix:</strong> {html.escape(patch.explanation)}</div>'
                                            f'</div>'
                                        )
                                        if fixes_state is None:
                                            c_app, c_rej, c_pen = st.columns(3)
                                            if c_app.button("✅ Approve", key=f"btn_app_{idx}_{patch.file}", disabled=(patch.status == "approved"), use_container_width=True):
                                                patch.status = "approved"
                                                _store("proposed_patches", proposed_state)
                                                st.rerun()
                                            if c_rej.button("❌ Reject", key=f"btn_rej_{idx}_{patch.file}", disabled=(patch.status == "rejected"), use_container_width=True):
                                                patch.status = "rejected"
                                                _store("proposed_patches", proposed_state)
                                                st.rerun()
                                            if c_pen.button("⏳ Mark Pending", key=f"btn_pen_{idx}_{patch.file}", disabled=(patch.status == "pending"), use_container_width=True):
                                                patch.status = "pending"
                                                _store("proposed_patches", proposed_state)
                                                st.rerun()
                                        else:
                                            st.caption(f"Review status is locked as **{status_label}** during isolated sandbox validation.")
                                else:
                                    _render_summary_row()

                approved_patches = [p for p in patches if p.status == "approved"]
                if fixes_state is None:
                    if approved_patches:
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
                        for k in list(st.session_state.keys()):
                            if str(k).startswith(("sl_patch_err_decisions_", "sl_patch_sel_")):
                                st.session_state.pop(k, None)
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
            report = _current_report(project)
            if report.final_status == "SAFE":
                st.success("🟢 **SAFE** — " + " ".join(report.status_reasons))
            elif report.final_status == "RISKY":
                st.error("🔴 **RISKY** — " + " ".join(report.status_reasons))
            else:
                st.warning("🟡 **INCOMPLETE** — " + " ".join(report.status_reasons))
            for error in report.errors:
                st.error(error)


imported_repos = list_imported_repos()
active_panel = st.session_state.get("sl_sidebar_panel", "explorer")
if active_panel not in {"explorer", "open", "settings"}:
    active_panel = "explorer"

drawer_open = bool(st.session_state.get("sl_drawer_open", True))
DRAWER_WIDTHS = [0.19, 0.24, 0.31]
drawer_width_idx = int(st.session_state.get("sl_drawer_width_idx", 1))
drawer_width_idx = max(0, min(len(DRAWER_WIDTHS) - 1, drawer_width_idx))

source_options = [
    "Java Samples (Semgrep*)",
    "GitHub Repository",
    "Python Samples (Bandit)",
    "Local Folder",
]
source_type = st.session_state.get("sl_active_source_type", source_options[0])
if source_type not in source_options:
    source_type = source_options[0]

if "sl_java_sample" not in st.session_state:
    st.session_state["sl_java_sample"] = JAVA_SAMPLE_NAMES[0]
if "sl_python_sample" not in st.session_state:
    st.session_state["sl_python_sample"] = PYTHON_SAMPLE_NAMES[0]
if "sl_local_folder_path" not in st.session_state:
    st.session_state["sl_local_folder_path"] = str(SAMPLE_ROOT / JAVA_SAMPLE_NAMES[0])
if "sl_gemini_model" not in st.session_state:
    st.session_state["sl_gemini_model"] = settings.gemini_model
if "sl_offline_mode" not in st.session_state:
    st.session_state["sl_offline_mode"] = settings.offline


def _reset_project_session() -> None:
    """Close previous editor tabs and clear per-project state when switching folders or branches."""
    preserved = {
        "sl_project_key",
        "sl_sidebar_panel",
        "sl_drawer_open",
        "sl_drawer_width_idx",
        "sl_active_source_type",
        "sl_java_sample",
        "sl_python_sample",
        "sl_selected_repo_id",
        "sl_code_font_size",
        "sl_local_folder_path",
        "sl_local_folder_input",
        "sl_gemini_model",
        "sl_gemini_model_input",
        "sl_offline_mode",
        "sl_offline_mode_input",
    }
    for key in list(st.session_state):
        if key.startswith("sl_") and key not in preserved:
            del st.session_state[key]


def _resolve_workspace_state() -> tuple[Path, object | None, list[str], list[str], str | None, int | None]:
    """Resolve active project path, repo metadata, filtered file list, open editor tabs, and focused file/line."""
    cur_source = st.session_state.get("sl_active_source_type", source_options[0])
    cur_repo = None
    if cur_source == "Java Samples (Semgrep*)":
        proj = SAMPLE_ROOT / st.session_state["sl_java_sample"]
    elif cur_source == "Python Samples (Bandit)":
        proj = SAMPLE_ROOT / st.session_state["sl_python_sample"]
    elif cur_source == "GitHub Repository" and imported_repos:
        repo_map = {r.id: r for r in imported_repos}
        rid = st.session_state.get("sl_selected_repo_id")
        cur_repo = repo_map.get(rid, imported_repos[0])
        proj = Path(cur_repo.local_path)
    elif cur_source == "Local Folder":
        proj = Path(st.session_state["sl_local_folder_path"]).expanduser()
    else:
        proj = SAMPLE_ROOT / st.session_state["sl_java_sample"]

    proj = proj.resolve()
    proj_key = str(proj)
    if st.session_state.get("sl_project_key") != proj_key:
        _reset_project_session()
        st.session_state["sl_project_key"] = proj_key

    files = list_repo_files(proj)
    if "sl_open_tabs" not in st.session_state:
        init_file = _pick_default_file(files) if files else None
        st.session_state["sl_open_tabs"] = [init_file] if init_file else []
        st.session_state["sl_focused_file"] = init_file
        st.session_state["sl_focused_line"] = None
    else:
        valid_tabs = [p for p in st.session_state["sl_open_tabs"] if p in files]
        st.session_state["sl_open_tabs"] = valid_tabs
        if st.session_state.get("sl_focused_file") not in files:
            st.session_state["sl_focused_file"] = valid_tabs[0] if valid_tabs else None
            st.session_state["sl_focused_line"] = None

    tabs: list[str] = st.session_state["sl_open_tabs"]
    f_file: str | None = st.session_state.get("sl_focused_file")
    if f_file and f_file in files and f_file not in tabs:
        tabs.append(f_file)
    f_line: int | None = st.session_state.get("sl_focused_line")
    return proj, cur_repo, files, tabs, f_file, f_line


if drawer_open:
    drawer_w = DRAWER_WIDTHS[drawer_width_idx]
    rail_col, drawer_col, editor_col = st.columns(
        [0.045, drawer_w, round(1.0 - 0.045 - drawer_w, 3)],
        gap="small",
    )
else:
    rail_col, editor_col = st.columns([0.045, 0.955], gap="small")
    drawer_col = None

with rail_col:
    with st.container(key="sl_activity_rail", gap=None):
        if not drawer_open:
            if st.button(
                "",
                icon=":material/left_panel_open:",
                key="rail_expand_btn",
                type="tertiary",
                use_container_width=True,
            ):
                st.session_state["sl_drawer_open"] = True
                st.rerun()
        rail_items = [
            ("explorer", ":material/file_copy:"),
            ("open", ":material/folder_open:"),
            ("settings", ":material/settings:"),
        ]
        for panel_id, icon_name in rail_items:
            is_selected = drawer_open and active_panel == panel_id
            if st.button(
                "",
                icon=icon_name,
                key=f"rail_btn_{panel_id}",
                type="primary" if is_selected else "tertiary",
                use_container_width=True,
            ):
                if drawer_open and active_panel == panel_id:
                    st.session_state["sl_drawer_open"] = False
                else:
                    st.session_state["sl_sidebar_panel"] = panel_id
                    st.session_state["sl_drawer_open"] = True
                st.rerun()

if drawer_col is not None:
    with drawer_col:
        with st.container(key="sl_drawer_panel", gap="small"):
            panel_titles = {
                "explorer": "EXPLORER",
                "open": "OPEN FILE / FOLDER",
                "settings": "SETTINGS",
            }
            hdr_title_col, hdr_narrow_col, hdr_wide_col, hdr_close_col = st.columns([3.8, 0.9, 0.9, 0.9])
            with hdr_title_col:
                st.caption(panel_titles[active_panel])
            with st.container(key="sl_drawer_controls"):
                with hdr_narrow_col:
                    if st.button(
                        "",
                        icon=":material/chevron_left:",
                        key="drawer_narrow_btn",
                        disabled=(drawer_width_idx <= 0),
                        use_container_width=True,
                    ):
                        st.session_state["sl_drawer_width_idx"] = max(0, drawer_width_idx - 1)
                        st.rerun()
                with hdr_wide_col:
                    if st.button(
                        "",
                        icon=":material/chevron_right:",
                        key="drawer_wide_btn",
                        disabled=(drawer_width_idx >= len(DRAWER_WIDTHS) - 1),
                        use_container_width=True,
                    ):
                        st.session_state["sl_drawer_width_idx"] = min(len(DRAWER_WIDTHS) - 1, drawer_width_idx + 1)
                        st.rerun()
                with hdr_close_col:
                    if st.button(
                        "",
                        icon=":material/left_panel_close:",
                        key="drawer_collapse_btn",
                        use_container_width=True,
                    ):
                        st.session_state["sl_drawer_open"] = False
                        st.rerun()

            if active_panel == "open":
                default_open_tab = (
                    "GitHub"
                    if source_type == "GitHub Repository"
                    else ("Local" if source_type == "Local Folder" else "Sample")
                )
                open_choice = st.radio(
                    "Open from",
                    ["Sample", "Local", "GitHub"],
                    index=["Sample", "Local", "GitHub"].index(default_open_tab),
                    horizontal=True,
                    label_visibility="collapsed",
                )

                if open_choice == "Sample":
                    sample_kind = st.radio(
                        "Language",
                        ["Java (Semgrep*)", "Python (Bandit)"],
                        index=0 if source_type != "Python Samples (Bandit)" else 1,
                        horizontal=True,
                        label_visibility="collapsed",
                    )
                    if sample_kind == "Java (Semgrep*)":
                        st.session_state["sl_active_source_type"] = "Java Samples (Semgrep*)"
                        cur_java = st.session_state["sl_java_sample"]
                        chosen_java = st.selectbox(
                            "Java sample",
                            JAVA_SAMPLE_NAMES,
                            index=JAVA_SAMPLE_NAMES.index(cur_java) if cur_java in JAVA_SAMPLE_NAMES else 0,
                        )
                        st.session_state["sl_java_sample"] = chosen_java
                        st.caption(SAMPLE_DESCRIPTIONS.get(chosen_java, ""))
                    else:
                        st.session_state["sl_active_source_type"] = "Python Samples (Bandit)"
                        cur_py = st.session_state["sl_python_sample"]
                        chosen_py = st.selectbox(
                            "Python sample",
                            PYTHON_SAMPLE_NAMES,
                            index=PYTHON_SAMPLE_NAMES.index(cur_py) if cur_py in PYTHON_SAMPLE_NAMES else 0,
                        )
                        st.session_state["sl_python_sample"] = chosen_py
                        st.caption(SAMPLE_DESCRIPTIONS.get(chosen_py, ""))

                elif open_choice == "Local":
                    st.session_state["sl_active_source_type"] = "Local Folder"
                    default_local = st.session_state["sl_local_folder_path"]

                    def _on_local_folder_input() -> None:
                        st.session_state["sl_local_folder_path"] = st.session_state["sl_local_folder_input"]

                    if st.button("Select from your files…", icon=":material/folder_open:", use_container_width=True):
                        chosen_dir = _pick_local_folder(default_local)
                        if chosen_dir:
                            st.session_state["sl_local_folder_path"] = chosen_dir
                            st.session_state["sl_local_folder_input"] = chosen_dir
                            _reset_project_session()
                            st.session_state["sl_sidebar_panel"] = "explorer"
                            st.rerun()

                    st.session_state["sl_local_folder_input"] = default_local
                    st.text_input(
                        "Folder path",
                        key="sl_local_folder_input",
                        on_change=_on_local_folder_input,
                    )

                else:
                    st.session_state["sl_active_source_type"] = "GitHub Repository"
                    gh_mode = st.radio(
                        "GitHub source",
                        ["Already cloned", "Clone from URL"] if imported_repos else ["Clone from URL"],
                        horizontal=True,
                        label_visibility="collapsed",
                    )
                    if gh_mode == "Already cloned" and imported_repos:
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
                        sel_repo = repo_map[chosen_label]
                        sel_path = Path(sel_repo.local_path)
                        branches = list_branches(sel_path)
                        cur_branch = sel_repo.current_branch if sel_repo.current_branch in branches else branches[0]
                        selected_branch = st.selectbox("Branch", branches, index=branches.index(cur_branch))
                        if selected_branch != sel_repo.current_branch:
                            if st.button(f"Switch to {selected_branch}", use_container_width=True):
                                try:
                                    checkout_branch(sel_path, selected_branch)
                                    _reset_project_session()
                                    st.success(f"Switched to {selected_branch}")
                                    st.rerun()
                                except Exception as exc:
                                    st.error(str(exc))
                    else:
                        gh_url = st.text_input("GitHub URL", placeholder="https://github.com/owner/repo")
                        gh_branch = st.text_input("Branch (optional)", placeholder="main")
                        if st.button("Clone & Open", use_container_width=True):
                            try:
                                with st.spinner("Cloning repository…"):
                                    imported = clone_or_open_repo(gh_url, branch=gh_branch or None)
                                    st.session_state["sl_active_source_type"] = "GitHub Repository"
                                    st.session_state["sl_selected_repo_id"] = imported.id
                                    _reset_project_session()
                                    st.session_state["sl_sidebar_panel"] = "explorer"
                                    st.rerun()
                            except Exception as exc:
                                st.error(f"Import failed: {exc}")

            elif active_panel == "settings":
                def _on_model_change() -> None:
                    st.session_state["sl_gemini_model"] = st.session_state["sl_gemini_model_input"]

                def _on_offline_change() -> None:
                    st.session_state["sl_offline_mode"] = st.session_state["sl_offline_mode_input"]

                st.session_state["sl_gemini_model_input"] = st.session_state["sl_gemini_model"]
                st.session_state["sl_offline_mode_input"] = st.session_state["sl_offline_mode"]
                st.text_input(
                    "Gemini model",
                    key="sl_gemini_model_input",
                    on_change=_on_model_change,
                )
                st.checkbox(
                    "Offline mode (cache only)",
                    key="sl_offline_mode_input",
                    on_change=_on_offline_change,
                )
                rule_count = len(list(SEMGREP_STAR_DIR.glob("*.yaml"))) if SEMGREP_STAR_DIR.is_dir() else 0
                st.caption(f"Scanners: Semgrep* ({rule_count} Java rules) & Bandit")

            project, active_repo, repo_files, open_tabs, focused_file, focused_line = _resolve_workspace_state()

            if active_panel == "open":
                st.divider()
                st.caption(f"Active: `{project.name}` ({len(repo_files)} file{'s' if len(repo_files) != 1 else ''})")
                if st.button(
                    "Open in Explorer",
                    icon=":material/file_copy:",
                    key="open_explorer_from_open",
                    use_container_width=True,
                ):
                    st.session_state["sl_sidebar_panel"] = "explorer"
                    st.rerun()

            if active_panel == "explorer":
                st.caption(f"{project.name} · {len(repo_files)} file{'s' if len(repo_files) != 1 else ''}")

                if not repo_files:
                    st.caption("No readable source files in this folder.")
                else:
                    def _on_file_selector_change() -> None:
                        _open_file_in_tab(st.session_state["sl_file_selector"])

                    selector_value = focused_file if focused_file in repo_files else repo_files[0]
                    st.session_state["sl_file_selector"] = selector_value
                    st.selectbox(
                        "Find file",
                        repo_files,
                        key="sl_file_selector",
                        on_change=_on_file_selector_change,
                        label_visibility="collapsed",
                    )

                    tree = _build_folder_tree(repo_files)
                    all_folder_keys = _collect_all_folder_keys(tree)
                    reveal_target = focused_file or repo_files[0]
                    if "sl_expanded_folders" not in st.session_state:
                        initial_expanded = {"__root__"}
                        initial_expanded.update(k for k in all_folder_keys if reveal_target.startswith(f"{k}/"))
                        st.session_state["sl_expanded_folders"] = initial_expanded
                        st.session_state["sl_tree_revealed_file"] = reveal_target
                    elif st.session_state.get("sl_tree_revealed_file") != reveal_target:
                        st.session_state["sl_expanded_folders"].add("__root__")
                        st.session_state["sl_expanded_folders"].update(
                            k for k in all_folder_keys if reveal_target.startswith(f"{k}/")
                        )
                        st.session_state["sl_tree_revealed_file"] = reveal_target

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
                                _open_file_in_tab(rel_path)
                                st.rerun()

                    with st.container(border=True, height=480, key="sl_tree_box", gap=None, horizontal_alignment="left"):
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
else:
    project, active_repo, repo_files, open_tabs, focused_file, focused_line = _resolve_workspace_state()

model_name = st.session_state["sl_gemini_model"]
offline = bool(st.session_state["sl_offline_mode"])

triage_key = f"{model_name}|{offline}"
if st.session_state.get("sl_config_key") not in (None, triage_key):
    st.session_state.pop("sl_triage", None)
    st.session_state.pop("sl_triage_done_key", None)
    st.session_state.pop("sl_proposed_patches", None)
    st.session_state.pop("sl_fixes", None)
st.session_state["sl_config_key"] = triage_key

client_settings = replace(load_settings(offline=offline), gemini_model=model_name)
llm_client = LLMClient(client_settings)

with editor_col:
    if not repo_files:
        if not drawer_open and st.button(
            "Open sidebar",
            icon=":material/left_panel_open:",
            key="editor_expand_btn_empty",
            type="secondary",
        ):
            st.session_state["sl_drawer_open"] = True
            st.rerun()
        st.warning(f"No readable source files found in `{project}`.")
    elif not open_tabs or focused_file is None:
        if not drawer_open and st.button(
            "Open sidebar",
            icon=":material/left_panel_open:",
            key="editor_expand_btn_no_tabs",
            type="secondary",
        ):
            st.session_state["sl_drawer_open"] = True
            st.rerun()
        st.info("Select a file from the Explorer tree on the left to open it in the editor.")
    else:
        with st.container(horizontal=True, gap=None, key="sl_editor_tabs"):
            if not drawer_open:
                if st.button(
                    "",
                    icon=":material/left_panel_open:",
                    key="editor_expand_btn",
                    type="tertiary",
                    width="content",
                ):
                    st.session_state["sl_drawer_open"] = True
                    st.rerun()
            for tab_path in open_tabs:
                tab_icon = "☕" if tab_path.endswith(".java") else ("🐍" if tab_path.endswith(".py") else "📄")
                tab_name = tab_path.rsplit("/", 1)[-1]
                is_active_tab = tab_path == focused_file
                if st.button(
                    f"{tab_icon} {tab_name}",
                    key=f"editor_tab__{tab_path}",
                    type="primary" if is_active_tab else "tertiary",
                    width="content",
                ):
                    if tab_path != focused_file:
                        st.session_state["sl_focused_file"] = tab_path
                        st.session_state["sl_focused_line"] = None
                        st.rerun()
                if st.button(
                    "✕",
                    key=f"close_tab__{tab_path}",
                    type="tertiary",
                    width="content",
                ):
                    remaining = [p for p in open_tabs if p != tab_path]
                    st.session_state["sl_open_tabs"] = remaining
                    if tab_path == focused_file:
                        st.session_state["sl_focused_file"] = remaining[-1] if remaining else None
                        st.session_state["sl_focused_line"] = None
                    st.rerun()

        font_size = int(st.session_state.get("sl_code_font_size", 14))
        breadcrumb = " › ".join(focused_file.split("/"))
        line_pill = (
            f'<span style="background:rgba(248,81,73,0.16);border:1px solid rgba(248,81,73,0.4);'
            f'color:#fca5a5;padding:1px 8px;border-radius:999px;font-size:11.5px;margin-left:8px;">'
            f'🎯 Line {focused_line}</span>'
            if focused_line
            else ""
        )

        crumb_col, zoom_out_col, zoom_val_col, zoom_in_col = st.columns([6.4, 0.7, 0.7, 0.7])
        with crumb_col:
            st.html(
                f'<div style="background:#161b22;border-left:1px solid rgba(255,255,255,0.10);'
                f'border-right:1px solid rgba(255,255,255,0.10);padding:6px 14px;display:flex;align-items:center;">'
                f'<span style="color:#8b949e;font-family:ui-monospace,monospace;font-size:12px;'
                f'white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{html.escape(breadcrumb)}</span>'
                f'{line_pill}'
                f'</div>'
            )
        with zoom_out_col:
            if st.button("A-", key="sl_zoom_out", disabled=(font_size <= 12), use_container_width=True):
                st.session_state["sl_code_font_size"] = max(12, font_size - 2)
                st.rerun()
        with zoom_val_col:
            st.markdown(f"<div style='text-align:center;padding-top:6px;font-size:13px;color:#8b949e;'>{font_size}px</div>", unsafe_allow_html=True)
        with zoom_in_col:
            if st.button("A+", key="sl_zoom_in", disabled=(font_size >= 22), use_container_width=True):
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

    _render_security_pipeline(project, llm_client, triage_key)
