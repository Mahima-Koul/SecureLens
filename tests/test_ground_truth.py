"""Validate sample ground-truth entries and source line hints."""

import json
from pathlib import Path


def test_each_sample_has_valid_ground_truth():
    sample_dirs = sorted(Path("samples").iterdir())
    assert {path.name for path in sample_dirs if path.is_dir()} == {
        "sqli_app", "cmdi_app", "secrets_deser_app", "wow_app"
    }
    for sample in sample_dirs:
        if not sample.is_dir():
            continue
        app = sample / "app.py"
        tests = sample / "tests" / "test_app.py"
        ground_truth = sample / "ground_truth.json"
        assert app.is_file() and tests.is_file() and ground_truth.is_file()
        payload = json.loads(ground_truth.read_text(encoding="utf-8"))
        assert isinstance(payload.get("expected_alerts"), list) and payload["expected_alerts"]
        source_lines = len(app.read_text(encoding="utf-8").splitlines())
        for alert in payload["expected_alerts"]:
            assert isinstance(alert.get("rule_id_or_category"), str) and alert["rule_id_or_category"]
            assert 1 <= alert.get("line_hint", 0) <= source_lines
            assert isinstance(alert.get("is_real"), bool)
            assert isinstance(alert.get("note"), str) and alert["note"]
