"""Stage 1: GitHub Repository Import, Branch Selection, and Managed Workspace Explorer."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlparse

GITHUB_URL_PATTERN = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)
IGNORED_TREE_DIRS = {
    ".git", ".venv", "venv", "__pycache__", ".cache", "workdir",
    "node_modules", "target", "build", ".idea", "tests", ".securelens-patched",
}
IGNORED_TREE_FILES = {"ground_truth.json", ".securelens-patched"}
TEXT_EXTENSIONS = {
    ".java", ".py", ".xml", ".yml", ".yaml", ".json", ".properties",
    ".md", ".txt", ".gradle", ".sh", ".html", ".js", ".ts", ".sql",
}


@dataclass
class ImportedRepo:
    """Metadata for a repository imported into the SecureLens managed workspace."""

    id: str
    label: str
    url: str
    owner: str
    name: str
    local_path: str
    current_branch: str = "main"
    branches: list[str] = field(default_factory=list)


def default_repos_root() -> Path:
    """Return the managed workspace root for cloned GitHub repositories."""
    root = Path.cwd() / "workdir" / "repos"
    root.mkdir(parents=True, exist_ok=True)
    return root


def validate_github_url(url: str) -> tuple[str, str, str]:
    """Validate an HTTPS GitHub repository URL and return (normalized_url, owner, repo_name)."""
    cleaned = (url or "").strip()
    if not cleaned:
        raise ValueError("GitHub repository URL cannot be empty.")
    parsed = urlparse(cleaned)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise ValueError("Only HTTPS github.com repository URLs are supported (e.g. https://github.com/owner/repo).")
    match = GITHUB_URL_PATTERN.match(cleaned)
    if not match:
        raise ValueError("Invalid GitHub repository URL format. Expected: https://github.com/<owner>/<repo>")
    owner = match.group("owner")
    repo = match.group("repo")
    if owner in {".", ".."} or repo in {".", ".."}:
        raise ValueError("Invalid owner or repository name in URL.")
    normalized = f"https://github.com/{owner}/{repo}.git"
    return normalized, owner, repo


def clone_or_open_repo(
    url: str,
    *,
    branch: str | None = None,
    repos_root: str | Path | None = None,
    timeout: int = 120,
) -> ImportedRepo:
    """Validate and clone a GitHub repository into the isolated managed workspace."""
    normalized_url, owner, repo_name = validate_github_url(url)
    workspace = Path(repos_root).resolve() if repos_root is not None else default_repos_root()
    workspace.mkdir(parents=True, exist_ok=True)

    folder_name = f"{owner}__{repo_name}"
    target_dir = (workspace / folder_name).resolve()
    try:
        target_dir.relative_to(workspace)
    except ValueError as exc:
        raise ValueError("Repository destination escapes managed workspace.") from exc

    if not (target_dir / ".git").is_dir():
        cmd = ["git", "clone", "--depth", "50", "--no-single-branch"]
        if branch and branch.strip():
            cmd.extend(["--branch", branch.strip()])
        cmd.extend([normalized_url, str(target_dir)])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()[-400:]
            raise RuntimeError(f"Git clone failed: {detail or 'unable to clone repository'}")

    if branch and branch.strip():
        checkout_branch(target_dir, branch.strip(), timeout=timeout)

    branches = list_branches(target_dir)
    current = get_current_branch(target_dir) or (branch or (branches[0] if branches else "main"))

    registry = _load_registry(workspace)
    existing = next((item for item in registry if item["local_path"] == str(target_dir)), None)
    if existing:
        existing["current_branch"] = current
        existing["branches"] = branches
        repo_record = ImportedRepo(**existing)
    else:
        index = len(registry) + 1
        repo_record = ImportedRepo(
            id=folder_name,
            label=f"Repo {index}: {owner}/{repo_name}",
            url=f"https://github.com/{owner}/{repo_name}",
            owner=owner,
            name=repo_name,
            local_path=str(target_dir),
            current_branch=current,
            branches=branches,
        )
        registry.append(asdict(repo_record))
    _save_registry(workspace, registry)
    return repo_record


def list_imported_repos(repos_root: str | Path | None = None) -> list[ImportedRepo]:
    """List all imported repositories tracked in the managed workspace."""
    workspace = Path(repos_root).resolve() if repos_root is not None else default_repos_root()
    records = _load_registry(workspace)
    active: list[ImportedRepo] = []
    for idx, item in enumerate(records, start=1):
        local = Path(item.get("local_path", ""))
        if local.is_dir():
            item["label"] = f"Repo {idx}: {item.get('owner', '')}/{item.get('name', local.name)}"
            item["current_branch"] = get_current_branch(local) or item.get("current_branch", "main")
            item["branches"] = list_branches(local) or item.get("branches", ["main"])
            active.append(ImportedRepo(**item))
    return active


def list_branches(repo_dir: str | Path) -> list[str]:
    """Return available local and remote branches for a cloned repository."""
    root = Path(repo_dir).resolve()
    if not (root / ".git").exists():
        return ["main"]
    result = subprocess.run(
        ["git", "-C", str(root), "branch", "-a", "--format=%(refname:short)"],
        capture_output=True, text=True, timeout=15, check=False,
    )
    if result.returncode != 0:
        return ["main"]
    branches: list[str] = []
    for line in result.stdout.splitlines():
        name = line.strip()
        if not name or name == "origin" or "HEAD" in name:
            continue
        if name.startswith("origin/"):
            name = name[len("origin/"):]
        if name and name != "origin" and name not in branches:
            branches.append(name)
    return branches or ["main"]


def get_current_branch(repo_dir: str | Path) -> str:
    """Return the currently checked-out branch name."""
    root = Path(repo_dir).resolve()
    if not (root / ".git").exists():
        return "main"
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else "main"


def checkout_branch(repo_dir: str | Path, branch: str, *, timeout: int = 30) -> str:
    """Safely switch a managed repository to the selected branch."""
    root = Path(repo_dir).resolve()
    cleaned = (branch or "").strip()
    if not cleaned or not re.match(r"^[A-Za-z0-9._/-]+$", cleaned) or ".." in cleaned:
        raise ValueError(f"Invalid branch name: {branch}")
    result = subprocess.run(
        ["git", "-C", str(root), "checkout", cleaned],
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[-300:]
        raise RuntimeError(f"Could not checkout branch '{cleaned}': {detail}")
    return get_current_branch(root)


def list_repo_files(repo_dir: str | Path) -> list[str]:
    """Return sorted project-relative file paths for the repository file explorer."""
    root = Path(repo_dir).resolve()
    if not root.is_dir():
        return []
    files: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            rel = path.resolve().relative_to(root)
        except ValueError:
            continue
        if any(part in IGNORED_TREE_DIRS or part.endswith("_patched") for part in rel.parts):
            continue
        if path.name in IGNORED_TREE_FILES:
            continue
        if path.suffix.lower() in TEXT_EXTENSIONS or path.name in {"Dockerfile", "Makefile", "pom.xml"}:
            files.append(rel.as_posix())
    return files


def read_repo_file(repo_dir: str | Path, relative_path: str) -> str:
    """Safely read a file inside a repository, rejecting path traversal."""
    root = Path(repo_dir).resolve()
    candidate = (root / relative_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"File path escapes repository root: {relative_path}") from exc
    if not candidate.is_file():
        raise FileNotFoundError(f"File not found in repository: {relative_path}")
    return candidate.read_text(encoding="utf-8", errors="replace")


def _registry_path(workspace: Path) -> Path:
    return workspace / "repos_registry.json"


def _load_registry(workspace: Path) -> list[dict]:
    path = _registry_path(workspace)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save_registry(workspace: Path, records: list[dict]) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    path = _registry_path(workspace)
    path.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
