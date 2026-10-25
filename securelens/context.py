"""Extract useful Python source context for a finding."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from .models import Finding


@dataclass
class Context:
    """Source evidence passed to triage and patch generation."""

    source: str
    imports: list[str]
    numbered_lines: str
    function_name: str | None


def extract_context(finding: Finding, project_dir: str | Path, radius: int = 8) -> Context:
    """Extract the enclosing function, imports, and nearby numbered lines."""
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
    try:
        tree = ast.parse("\n".join(lines), filename=str(path))
        imports = ["\n".join(lines[node.lineno - 1:node.end_lineno]) for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom)) and node.end_lineno]
        functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= finding.line <= node.end_lineno]
        if functions:
            node = min(functions, key=lambda function: function.end_lineno - function.lineno)
            finding.function_name = node.name
            source = "\n".join(lines[node.lineno - 1:node.end_lineno])
            return Context(source=source, imports=imports, numbered_lines=numbered, function_name=node.name)
        return Context(source=numbered, imports=imports, numbered_lines=numbered, function_name=None)
    except (SyntaxError, ValueError):
        return Context(source=numbered, imports=[], numbered_lines=numbered, function_name=None)
