"""Run the reproducible SecureLens sample evaluation and write JSON/Markdown."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from securelens.config import load_settings
from securelens.pipeline import run_pipeline

SAMPLES = ("sqli_app", "cmdi_app", "secrets_deser_app", "wow_app")
CATEGORY_RULES = {
    "sql-injection": {"b608"},
    "command-injection": {"b602", "b603", "b605"},
    "hardcoded-secret": {"b105", "b106", "b107"},
    "unsafe-deserialization": {"b301", "b302", "b303"},
    "weak-hash": {"b324", "b505"},
    "unsafe-evaluation": {"b307"},
}


def _matching_finding(alert: dict[str, Any], findings: list[Any]) -> Any | None:
    needle = str(alert.get("rule_id_or_category", "")).lower().replace("_", "-")
    rules = CATEGORY_RULES.get(needle, set())
    candidates = [finding for finding in findings if needle and (
        needle in finding.rule_id.lower().replace("_", "-")
        or needle in finding.message.lower().replace("_", "-")
        or finding.rule_id.lower() in rules
    )]
    hint = alert.get("line_hint")
    if hint is not None:
        nearby = [item for item in candidates if abs(item.line - int(hint)) <= 8]
        if nearby:
            candidates = nearby
    return min(candidates, key=lambda item: abs(item.line - int(hint or item.line))) if candidates else None


def evaluate_sample(name: str, *, offline: bool) -> dict[str, Any]:
    project = ROOT / "samples" / name
    ground_truth = json.loads((project / "ground_truth.json").read_text(encoding="utf-8"))
    started = time.perf_counter()
    report = run_pipeline(project, offline=offline)
    duration = time.perf_counter() - started
    expected = ground_truth.get("expected_alerts", [])
    matched = [(item, _matching_finding(item, report.findings)) for item in expected]
    real = [(item, finding) for item, finding in matched if item.get("is_real")]
    false = [(item, finding) for item, finding in matched if not item.get("is_real")]
    verdict_by_id = {item.finding_id: item for item in report.verdicts}
    complete = (
        report.final_status != "INCOMPLETE" and report.diff is not None and report.regression is not None
        and report.regression.original.errors == 0 and report.regression.patched.errors == 0
        and not any("Semgrep failed" in error or "Bandit failed" in error for error in report.errors)
    )
    false_removed = sum(
        finding is not None and finding.id in verdict_by_id
        and finding in report.dismissed and finding not in report.unresolved
        for _, finding in false
    )
    real_dismissed = sum(
        finding is not None and finding in report.dismissed and finding not in report.unresolved
        for _, finding in real
    )
    return {
        "sample": name,
        "status": report.final_status,
        "complete": complete,
        "alerts_before_filtering": len(report.findings),
        "false_positives_removed": false_removed if complete else None,
        "real_vulnerabilities_dismissed": real_dismissed if complete else None,
        "alerts_after_filtering": len(report.confirmed) if complete else None,
        "fixed": len(report.diff.fixed) if complete else None,
        "remaining": len(report.diff.remaining) if complete else None,
        "new": len(report.diff.new) if complete else None,
        "tests_before": report.regression.original.model_dump(mode="json") if complete else None,
        "tests_after": report.regression.patched.model_dump(mode="json") if complete else None,
        "newly_failing_tests": report.regression.newly_failing if complete else None,
        "duration_seconds": round(duration, 3),
        "llm": {
            "cache_hits": report.llm_stats.get("cache_hits", 0),
            "cache_misses": report.llm_stats.get("cache_misses", 0),
            "fresh_api_calls": report.llm_stats.get("api_calls", 0),
        },
        "ground_truth": {
            "expected_alerts": len(expected),
            "matched_alerts": sum(finding is not None for _, finding in matched),
            "unmatched": [item for item, finding in matched if finding is None],
        },
        "errors": report.errors,
    }


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# SecureLens evaluation results", "",
        f"Generated: {result['generated_at']}",
        f"Mode: {'offline/cache only' if result['offline'] else 'configured API/cache'}", "",
        "Incomplete runs use `null` for unavailable outcome metrics; this is not a zero.", "",
        "| Sample | Status | Alerts | FP removed | Real dismissed | Fixed | Remaining | New | Tests before/after | Seconds | LLM hits/misses/API |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in result["samples"]:
        test_counts = "unknown"
        if row["tests_before"] is not None:
            test_counts = f"{row['tests_before']['passed']}/{row['tests_after']['passed']} passed"
        llm = row["llm"]
        fields = [row["alerts_before_filtering"], row["false_positives_removed"],
                  row["real_vulnerabilities_dismissed"], row["fixed"], row["remaining"], row["new"]]
        fmt = lambda value: "unknown" if value is None else str(value)
        lines.append(
            f"| {row['sample']} | {row['status']} | {fmt(fields[0])} | {fmt(fields[1])} | "
            f"{fmt(fields[2])} | {fmt(fields[3])} | {fmt(fields[4])} | {fmt(fields[5])} | "
            f"{test_counts} | {row['duration_seconds']:.3f} | "
            f"{llm['cache_hits']}/{llm['cache_misses']}/{llm['fresh_api_calls']} |"
        )
    aggregate = result["aggregate"]
    total = lambda key: "unknown" if aggregate[key] is None else str(aggregate[key])
    lines.append(
        f"| **Total ({aggregate['completed_samples']}/{aggregate['sample_count']} complete)** | — | "
        f"{total('alerts_before_filtering')} | {total('false_positives_removed')} | "
        f"{total('real_vulnerabilities_dismissed')} | {total('fixed')} | {total('remaining')} | "
        f"{total('new')} | {total('tests_before_passed')}/{total('tests_after_passed')} passed | "
        f"{aggregate['duration_seconds']:.3f} | "
        f"{aggregate['llm']['cache_hits']}/{aggregate['llm']['cache_misses']}/{aggregate['llm']['fresh_api_calls']} |"
    )
    lines.extend(["", "## Diagnostics", ""])
    for row in result["samples"]:
        lines.append(f"### {row['sample']} — {row['status']}")
        lines.append(f"Ground truth matched {row['ground_truth']['matched_alerts']}/{row['ground_truth']['expected_alerts']} expected alerts.")
        if row["errors"]:
            lines.extend(f"- {error}" for error in row["errors"])
        else:
            lines.append("- No pipeline errors.")
        lines.append("")
    return "\n".join(lines)


def aggregate_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate measured values while keeping any partially unavailable metric unknown."""
    metric_keys = (
        "alerts_before_filtering", "false_positives_removed", "real_vulnerabilities_dismissed",
        "alerts_after_filtering", "fixed", "remaining", "new",
    )
    aggregate: dict[str, Any] = {
        "sample_count": len(rows),
        "completed_samples": sum(row["complete"] for row in rows),
        "duration_seconds": round(sum(row["duration_seconds"] for row in rows), 3),
        "llm": {key: sum(row["llm"][key] for row in rows)
                for key in ("cache_hits", "cache_misses", "fresh_api_calls")},
    }
    for key in metric_keys:
        values = [row[key] for row in rows]
        aggregate[key] = sum(values) if all(value is not None for value in values) else None
    for key, stage in (("tests_before_passed", "tests_before"), ("tests_after_passed", "tests_after")):
        values = [row[stage]["passed"] if row[stage] is not None else None for row in rows]
        aggregate[key] = sum(values) if all(value is not None for value in values) else None
    return aggregate


def main() -> int:
    offline = load_settings().offline
    rows = [evaluate_sample(name, offline=offline) for name in SAMPLES]
    result = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "offline": offline,
        "samples": rows,
        "aggregate": aggregate_rows(rows),
    }
    out = ROOT / "eval"
    out.mkdir(exist_ok=True)
    (out / "results.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out / "results.md").write_text(render_markdown(result), encoding="utf-8")
    print(f"Wrote {out / 'results.json'} and {out / 'results.md'}")
    print(render_markdown(result))
    return 0 if all(row["complete"] for row in rows) else 2


if __name__ == "__main__":
    raise SystemExit(main())
