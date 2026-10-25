"""Command execution demo with a user-controlled flaw and constant-command trap."""

import subprocess


def echo_user_text(text: str) -> str:
    """Echo untrusted text through a shell command (intentional demo flaw)."""
    result = subprocess.run(f"echo {text}", shell=True, capture_output=True, text=True, check=False)
    return result.stdout.strip()


def fixed_status_message() -> str:
    """Run a constant command; no user input reaches the shell."""
    result = subprocess.run("echo ready", shell=True, capture_output=True, text=True, check=False)
    return result.stdout.strip()


def normalize_label(text: str) -> str:
    """Normalize display text without executing it."""
    return " ".join(text.split())


def command_available() -> bool:
    """Return whether the harmless status command succeeded."""
    try:
        return subprocess.run("echo ready", shell=True, capture_output=True, check=False).returncode == 0
    except OSError:
        return False


def display_text(text: str, limit: int = 80) -> str:
    """Trim long text before showing it in a demonstration UI."""
    normalized = normalize_label(text)
    return normalized if len(normalized) <= limit else normalized[: limit - 1] + "…"


def is_short_label(text: str, limit: int = 80) -> bool:
    """Validate display length; this does not make shell input safe."""
    return len(normalize_label(text)) <= limit


def input_summary(text: str) -> str:
    """Return a display-only count of input characters."""
    return f"{len(text)} characters"
