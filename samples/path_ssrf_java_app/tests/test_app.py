from pathlib import Path


def _source() -> str:
    return (Path(__file__).resolve().parents[1] / "App.java").read_text(encoding="utf-8")


def test_report_file_and_webhook_methods_exist():
    src = _source()
    assert "resolveReportFile(String fileName)" in src
    assert "/var/app/reports" in src
    assert "buildWebhookUrl(String endpointUrl)" in src
    assert "getSearchUrl()" in src
    assert '"/docs/public/search"' in src
