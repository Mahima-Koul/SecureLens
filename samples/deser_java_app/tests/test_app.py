from pathlib import Path


def _source() -> str:
    return (Path(__file__).resolve().parents[1] / "App.java").read_text(encoding="utf-8")


def test_yaml_loader_and_username_validator_signatures_preserved():
    src = _source()
    assert "loadProfileYaml(String untrustedYaml)" in src
    assert "isValidUsername(String username)" in src
    assert "^[a-zA-Z0-9_]{3,16}$" in src
