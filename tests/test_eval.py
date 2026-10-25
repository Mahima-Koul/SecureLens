from eval.run_eval import aggregate_rows, _matching_finding
from securelens.models import Finding


def _row(*, complete=True):
    return {
        "sample": "demo",
        "complete": complete,
        "alerts_before_filtering": 2,
        "false_positives_removed": 1 if complete else None,
        "real_vulnerabilities_dismissed": 0 if complete else None,
        "alerts_after_filtering": 1 if complete else None,
        "fixed": 1 if complete else None,
        "remaining": 0 if complete else None,
        "new": 0 if complete else None,
        "tests_before": {"passed": 4} if complete else None,
        "tests_after": {"passed": 4} if complete else None,
        "duration_seconds": 1.0,
        "llm": {"cache_hits": 2, "cache_misses": 3, "fresh_api_calls": 1},
    }


def test_eval_aggregate_keeps_partial_outcomes_unknown():
    result = aggregate_rows([_row(), _row(complete=False)])
    assert result["alerts_before_filtering"] == 4
    assert result["fixed"] is None
    assert result["tests_before_passed"] is None
    assert result["completed_samples"] == 1
    assert result["llm"]["fresh_api_calls"] == 2


def test_eval_matches_ground_truth_category_to_bandit_rule():
    finding = Finding(
        id="x", tool="bandit", rule_id="B608", file="app.py", line=17,
        severity="MEDIUM", message="SQL injection", snippet="execute(query)", fingerprint="fp",
    )
    assert _matching_finding({"rule_id_or_category": "sql-injection", "line_hint": 17}, [finding]) == finding
