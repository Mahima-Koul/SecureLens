from types import SimpleNamespace
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import command_available, echo_user_text, fixed_status_message, normalize_label


def test_user_text_command_uses_expected_shell_string(monkeypatch):
    seen = {}
    def fake_run(command, **kwargs):
        seen["command"] = command
        return SimpleNamespace(stdout="hello\n")
    monkeypatch.setattr("app.subprocess.run", fake_run)
    assert echo_user_text("hello") == "hello"
    assert seen["command"] == "echo hello"


def test_hardcoded_command_is_constant(monkeypatch):
    seen = []
    def fake_run(command, **kwargs):
        seen.append(command)
        return SimpleNamespace(stdout="ready\n")
    monkeypatch.setattr("app.subprocess.run", fake_run)
    assert fixed_status_message() == "ready"
    assert seen == ["echo ready"]


def test_normalize_label_collapses_whitespace():
    assert normalize_label("  hello   world ") == "hello world"


def test_command_available_handles_success(monkeypatch):
    monkeypatch.setattr("app.subprocess.run", lambda *args, **kwargs: SimpleNamespace(returncode=0))
    assert command_available()
