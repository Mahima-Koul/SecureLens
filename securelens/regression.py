"""Run pytest in isolated subprocesses and compare failing test identities."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from .config import load_settings
from .models import RegressionResult, TestResult


def run_tests(project_dir: str | Path, *, timeout: int | None = None) -> TestResult:
    """Run `python -m pytest` in the requested project and parse JUnit XML."""
    root = Path(project_dir).resolve()
    if not root.is_dir():
        return TestResult(errors=1, raw_output_tail=f"Project directory does not exist: {root}")
    limit = timeout or load_settings().tool_timeout
    try:
        with tempfile.TemporaryDirectory(prefix="securelens-tests-") as temp_dir:
            xml_path = Path(temp_dir) / "results.xml"
            command = [
                sys.executable, "-m", "pytest", "-q", "--tb=short", "-rf",
                f"--junitxml={xml_path}", "-p", "no:cacheprovider",
            ]
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            environment["PYTHONPATH"] = str(root) + os.pathsep + environment.get("PYTHONPATH", "")
            environment.pop("PYTEST_ADDOPTS", None)
            completed = subprocess.run(
                command, cwd=root, env=environment, capture_output=True, text=True,
                timeout=limit, check=False,
            )
            output = (completed.stdout or "") + (completed.stderr or "")
            if xml_path.is_file():
                result = _parse_junit(xml_path, output)
                if completed.returncode and not (result.failed or result.errors):
                    result.errors = 1
                    result.raw_output_tail = _tail(output) or f"pytest exited with status {completed.returncode}"
                return result
            return _fallback_parse(output, completed.returncode)
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") + (exc.stderr or "")
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return TestResult(errors=1, raw_output_tail=f"pytest exceeded the {limit}s timeout.\n{_tail(output)}")
    except Exception as exc:
        return TestResult(errors=1, raw_output_tail=f"pytest could not run ({type(exc).__name__}).")


def compare_tests(original: TestResult, patched: TestResult) -> RegressionResult:
    """Compare test identities and report only failures introduced afterward."""
    before = set(original.failed_tests)
    newly_failing = sorted(set(patched.failed_tests) - before)
    return RegressionResult(original=original, patched=patched, newly_failing=newly_failing)


def _parse_junit(path: Path, output: str) -> TestResult:
    """Parse one pytest JUnit XML file, tolerating suite/group wrappers."""
    root = ET.parse(path).getroot()
    cases = list(root.iter("testcase"))
    passed = failed = errors = 0
    failed_tests: list[str] = []
    for case in cases:
        identity = f"{case.get('classname', '')}::{case.get('name', 'unknown')}"
        failure = case.find("failure")
        error = case.find("error")
        skipped = case.find("skipped")
        if failure is not None:
            failed += 1
            failed_tests.append(identity)
        elif error is not None:
            errors += 1
            failed_tests.append(identity)
        elif skipped is None:
            passed += 1
    # Collection and session errors may be reported on the suites, without testcase nodes.
    suite_errors = max((int(suite.get("errors", "0")) for suite in root.iter()
                        if suite.tag in {"testsuite", "testsuites"}), default=0)
    if suite_errors and errors == 0:
        errors = suite_errors
        failed_tests.append("pytest::collection-or-session-error")
    return TestResult(passed=passed, failed=failed, errors=errors,
                      failed_tests=failed_tests, raw_output_tail=_tail(output))


def _fallback_parse(output: str, return_code: int) -> TestResult:
    """Produce useful counts when pytest failed before writing JUnit XML."""
    match = re.search(r"(?P<passed>\d+) passed(?:, (?P<failed>\d+) failed)?(?:, (?P<errors>\d+) error)?", output)
    if not match:
        return TestResult(errors=1, raw_output_tail=_tail(output) or f"pytest exited with status {return_code} without JUnit results")
    return TestResult(
        passed=int(match.group("passed") or 0), failed=int(match.group("failed") or 0),
        errors=int(match.group("errors") or 0), raw_output_tail=_tail(output),
    )


def _tail(output: str, limit: int = 4000) -> str:
    """Keep only the end of tool output for concise diagnostics."""
    return output[-limit:].strip()
