from pathlib import Path


def _source() -> str:
    return (Path(__file__).resolve().parents[1] / "App.java").read_text(encoding="utf-8")


def test_invoice_parser_signature_and_parse_call_preserved():
    src = _source()
    assert "parseInvoiceXml(InputStream xmlStream)" in src
    assert ".parse(xmlStream)" in src


def test_health_endpoint_returns_ready():
    src = _source()
    assert "healthStatus()" in src
    assert '"READY"' in src
