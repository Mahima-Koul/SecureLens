"""Run Semgrep and Bandit and normalize their JSON findings."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import warnings
from pathlib import Path
from typing import Any

from .config import load_settings
from .models import Finding

IGNORED_PARTS = {"tests", "test", ".venv", "venv", "__pycache__", ".cache", "workdir"}


def scan_project(project_dir: str | Path) -> tuple[list[Finding], list[str]]:
    """Return normalized findings and scanner diagnostics without hiding failures."""
    root = Path(project_dir).resolve()
    if not root.is_dir():
        return [], [f"Project directory does not exist: {root}"]
    settings = load_settings()
    errors: list[str] = []
    raw: list[Finding] = []
    semgrep, semgrep_error = _run_semgrep(root, settings.tool_timeout, settings.semgrep_config)
    if semgrep_error:
        errors.append(semgrep_error)
    else:
        raw.extend(_normalize_semgrep(semgrep, root))
    bandit, bandit_error = _run_bandit(root, settings.tool_timeout)
    if bandit_error:
        errors.append(bandit_error)
    else:
        raw.extend(_normalize_bandit(bandit, root))
    return _deduplicate(raw), errors


def run_scan(project_dir: str | Path) -> list[Finding]:
    """Run available scanners and return normalized findings."""
    findings, errors = scan_project(project_dir)
    for error in errors:
        warnings.warn(error, RuntimeWarning, stacklevel=2)
    return findings


def _run_semgrep(root: Path, timeout: int, config_override: str | None) -> tuple[dict[str, Any] | None, str | None]:
    """Run Semgrep, retrying its default registry config with auto on fetch failure."""
    config = config_override or "p/python"
    semgrep_path = shutil.which("semgrep") or str(Path(sys.executable).with_name("semgrep.exe"))
    base = [semgrep_path, "scan", "--json", "--quiet", "--metrics", "off", "--config", config]
    try:
        result = subprocess.run(base + _excludes() + [str(root)], capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return None, "Semgrep is not installed; install requirements.txt to enable this scanner."
    except subprocess.TimeoutExpired:
        return None, f"Semgrep exceeded the {timeout}s timeout."
    if result.returncode == 0:
        try:
            return json.loads(result.stdout or "{}"), None
        except json.JSONDecodeError:
            return None, "Semgrep returned invalid JSON."
    diagnostic = (result.stderr or result.stdout or "").strip()[-1000:]
    if not config_override and any(token in diagnostic.lower() for token in ("network", "fetch", "registry", "resolve")):
        warnings.warn("Semgrep p/python registry config could not be fetched; retrying with --config auto.", RuntimeWarning)
        try:
            fallback = subprocess.run(["semgrep", "scan", "--json", "--quiet", "--metrics", "off", "--config", "auto", *_excludes(), str(root)], capture_output=True, text=True, timeout=timeout)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return None, f"Semgrep auto fallback failed: {type(exc).__name__}."
        if fallback.returncode == 0:
            try:
                return json.loads(fallback.stdout or "{}"), None
            except json.JSONDecodeError:
                return None, "Semgrep auto fallback returned invalid JSON."
        diagnostic = (fallback.stderr or fallback.stdout or diagnostic).strip()[-1000:]
    return None, f"Semgrep failed (exit {result.returncode}): {diagnostic or 'no diagnostic output'}"


def _run_bandit(root: Path, timeout: int) -> tuple[dict[str, Any] | None, str | None]:
    """Run Bandit recursively in JSON mode."""
    try:
        result = subprocess.run([sys.executable, "-m", "bandit", "-r", str(root), "-f", "json", "-x", "tests,*/.venv/*,*/venv/*,*/.cache/*,*/workdir/*"], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"Bandit exceeded the {timeout}s timeout."
    if result.returncode in (0, 1):
        try:
            return json.loads(result.stdout or "{}"), None
        except json.JSONDecodeError:
            return None, "Bandit returned invalid JSON."
    return None, f"Bandit failed (exit {result.returncode}): {(result.stderr or result.stdout).strip()[-1000:]}"


def _excludes() -> list[str]:
    """Build scanner excludes for non-production and generated files."""
    excludes: list[str] = []
    for name in sorted(IGNORED_PARTS):
        excludes.extend(["--exclude", name])
    excludes.extend(["--exclude", "*_patched", "--exclude", "test_*.py", "--exclude", "*_test.py"])
    return excludes


def _relative_file(path_value: str, root: Path) -> str | None:
    """Resolve a scanner path beneath the selected project, rejecting traversal."""
    candidate = Path(path_value)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        relative = candidate.resolve().relative_to(root)
    except (OSError, ValueError):
        return None
    if any(part in IGNORED_PARTS or part.endswith("_patched") for part in relative.parts):
        return None
    if relative.suffix.lower() != ".py":
        return None
    if relative.name.startswith("test_") or relative.name.endswith("_test.py"):
        return None
    return relative.as_posix()


def _severity(value: str | None) -> str:
    """Normalize scanner severity labels."""
    label = (value or "").upper()
    if label in {"ERROR", "CRITICAL", "HIGH", "SEVERE"}:
        return "HIGH"
    if label in {"WARNING", "MEDIUM", "MODERATE"}:
        return "MEDIUM"
    return "LOW"


def _stable_id(tool: str, rule: str, file: str, line: int, message: str) -> str:
    import hashlib
    return hashlib.sha1(f"{tool}\0{rule}\0{file}\0{line}\0{message}".encode()).hexdigest()


def _normalize_semgrep(data: dict[str, Any], root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for item in data.get("results", []):
        path = _relative_file(str(item.get("path", "")), root)
        if path is None:
            continue
        extra = item.get("extra", {})
        rule = str(item.get("check_id", "unknown"))
        line = int((item.get("start") or {}).get("line", 1))
        message = str(extra.get("message", rule))
        severity = _severity(extra.get("severity"))
        snippet = str(extra.get("lines", ""))
        findings.append(Finding(id=_stable_id("semgrep", rule, path, line, message), tool="semgrep", rule_id=rule, file=path, line=line, severity=severity, message=message, snippet=snippet, fingerprint=_fingerprint(rule, snippet)))
    return findings


def _normalize_bandit(data: dict[str, Any], root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for item in data.get("results", []):
        path = _relative_file(str(item.get("filename", "")), root)
        if path is None:
            continue
        rule = str(item.get("test_id", "unknown"))
        line = int(item.get("line_number", 1))
        message = str(item.get("issue_text", rule))
        severity = _severity(item.get("issue_severity"))
        snippet = str(item.get("code", "")).strip()
        findings.append(Finding(id=_stable_id("bandit", rule, path, line, message), tool="bandit", rule_id=rule, file=path, line=line, severity=severity, message=message, snippet=snippet, fingerprint=_fingerprint(rule, snippet)))
    return findings


def _fingerprint(rule: str, snippet: str) -> str:
    import hashlib
    normalized = re.sub(r"\s+", " ", snippet).strip()
    return hashlib.sha1(f"{rule}{normalized}".encode()).hexdigest()


def _category(rule: str, message: str) -> str:
    """Extract a broad weakness category for cross-tool alert deduplication."""
    match = re.search(r"CWE[-_ ]?(\d+)", f"{rule} {message}", re.IGNORECASE)
    if match:
        return f"CWE-{match.group(1)}"
    text = f"{rule} {message}".lower()
    for category, terms in {
        "injection": ("sql", "shell", "command injection", "subprocess"),
        "deserialization": ("pickle", "deserializ"),
        "secret": ("secret", "password", "api key", "credential"),
        "weak-hash": ("md5", "sha1", "weak hash", "hashlib"),
    }.items():
        if any(term in text for term in terms):
            return category
    return re.sub(r"[^a-z0-9]+", " ", rule.lower()).strip()


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Deduplicate overlapping scanner alerts by file, line, and CWE-like category."""
    result: list[Finding] = []
    severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    for item in findings:
        category = _category(item.rule_id, item.message)
        match_index = next((index for index, current in enumerate(result)
                            if current.tool != item.tool and current.file == item.file
                            and current.line == item.line
                            and _category(current.rule_id, current.message) == category), None)
        if match_index is None:
            result.append(item)
            continue
        current = result[match_index]
        chosen = item if severity_rank[item.severity] > severity_rank[current.severity] else current
        other = current if chosen is item else item
        chosen.message = f"{chosen.message} (overlapping {other.tool} alert {other.rule_id}: {other.message})"
        chosen.fingerprint = _fingerprint(chosen.rule_id, chosen.snippet)
        result[match_index] = chosen
    return sorted(result, key=lambda finding: (finding.file, finding.line, finding.tool, finding.rule_id))
