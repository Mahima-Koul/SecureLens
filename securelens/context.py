"""Extract useful Python or Java source context for a finding."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from .models import Finding

_JAVA_METHOD_SIG = re.compile(
    r"^\s*(?:(?:public|protected|private|static|final|synchronized|abstract|native)\s+)+"
    r"(?:<[^>]+>\s+)?(?:[\w\[\]<>.,\s]+?\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*\([^;]*\)\s*(?:throws\s+[\w.,\s]+)?\s*\{?"
)


@dataclass
class Context:
    """Source evidence passed to triage and patch generation."""

    source: str
    imports: list[str]
    numbered_lines: str
    function_name: str | None


def extract_context(finding: Finding, project_dir: str | Path, radius: int = 8) -> Context:
    """Extract the enclosing function/method, imports, and nearby numbered lines."""
    root = Path(project_dir).resolve()
    path = (root / finding.file).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError("Finding path escapes the selected project") from exc
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    first = max(1, finding.line - radius)
    last = min(len(lines), finding.line + radius)
    numbered = "\n".join(f"{number:4}: {lines[number - 1]}" for number in range(first, last + 1))

    if path.suffix.lower() == ".java":
        return _extract_java_context(finding, lines, numbered)

    try:
        tree = ast.parse("\n".join(lines), filename=str(path))
        imports = [
            "\n".join(lines[node.lineno - 1:node.end_lineno])
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom)) and node.end_lineno
        ]
        functions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.lineno <= finding.line <= node.end_lineno
        ]
        if functions:
            node = min(functions, key=lambda function: function.end_lineno - function.lineno)
            finding.function_name = node.name
            source = "\n".join(lines[node.lineno - 1:node.end_lineno])
            return Context(source=source, imports=imports, numbered_lines=numbered, function_name=node.name)
        return Context(source=numbered, imports=imports, numbered_lines=numbered, function_name=None)
    except (SyntaxError, ValueError):
        return Context(source=numbered, imports=[], numbered_lines=numbered, function_name=None)


def _extract_java_context(finding: Finding, lines: list[str], numbered: str) -> Context:
    """Extract Java package/import statements and the enclosing Java method block."""
    imports = [
        line.strip()
        for line in lines
        if line.strip().startswith(("import ", "package "))
    ]
    method_name, start_line, end_line = _find_enclosing_java_method(lines, finding.line)
    if method_name and start_line and end_line:
        finding.function_name = method_name
        source = "\n".join(lines[start_line - 1:end_line])
        return Context(source=source, imports=imports, numbered_lines=numbered, function_name=method_name)
    return Context(source=numbered, imports=imports, numbered_lines=numbered, function_name=None)


def _find_enclosing_java_method(lines: list[str], target_line: int) -> tuple[str | None, int | None, int | None]:
    """Locate the enclosing Java method around target_line using brace-depth tracking."""
    best: tuple[str | None, int | None, int | None] = (None, None, None)
    n = len(lines)
    # Start search a couple lines below target_line in case the finding is on an @Annotation line above the method signature
    search_start = min(target_line + 2, n) - 1
    for idx in range(search_start, -1, -1):
        line_text = lines[idx]
        stripped = line_text.strip()
        if not stripped or stripped.startswith(("//", "/*", "*", "@")):
            continue
        if any(keyword in stripped for keyword in ("class ", "interface ", "enum ")):
            continue
        match = _JAVA_METHOD_SIG.match(line_text)
        if not match:
            continue
        name = match.group("name")
        if name in {"if", "for", "while", "switch", "catch", "synchronized"}:
            continue
        start_idx = idx
        while start_idx > 0 and lines[start_idx - 1].strip().startswith("@"):
            start_idx -= 1
        depth = 0
        opened = False
        end_idx = None
        for scan_idx in range(idx, n):
            for ch in lines[scan_idx]:
                if ch == "{":
                    depth += 1
                    opened = True
                elif ch == "}":
                    depth -= 1
            if opened and depth <= 0:
                end_idx = scan_idx
                break
        if end_idx is not None and (start_idx + 1) <= target_line <= (end_idx + 1):
            best = (name, start_idx + 1, end_idx + 1)
            break
    return best
