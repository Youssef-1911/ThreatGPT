"""git_service.py — Repository code fetching for analysis.

Responsibility: clone or pull a repository, extract relevant source files,
and return them in a format the document ingestion pipeline can consume.

The webhook is a TRIGGER only. This module provides the actual CODE that
gets fed to the parsing engine, not the webhook JSON.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# File-type classification
# ---------------------------------------------------------------------------

# Extensions we extract — source code, configs, infra, docs.
# Anything not listed here is silently skipped.
_INCLUDED_EXTENSIONS: frozenset[str] = frozenset(
    {
        # Backend source
        ".py", ".go", ".java", ".cs", ".rb", ".rs", ".php", ".swift", ".kt",
        # Frontend source
        ".ts", ".tsx", ".js", ".jsx", ".vue", ".svelte",
        # Infrastructure / config
        ".yaml", ".yml", ".tf", ".tfvars", ".toml", ".ini",
        ".json",  # package.json, tsconfig, openapi specs, etc.
        # Documentation
        ".md", ".txt",
        # Shell / CI
        ".sh", ".bash",
        # SQL
        ".sql",
    }
)

# Directories that never contain analysis-relevant files.
_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git", "node_modules", ".venv", "venv", "__pycache__",
        ".pytest_cache", "dist", "build", ".next", ".nuxt",
        "coverage", ".tox", "vendor", "migrations", "alembic",
        "fixtures", "mocks", "__mocks__", ".github", ".circleci",
        "htmlcov", "site-packages",
    }
)

# Individual filenames (no extension) that are useful for analysis.
_INCLUDE_BARE_NAMES: frozenset[str] = frozenset(
    {"dockerfile", "makefile", "jenkinsfile", "procfile", "vagrantfile"}
)

# Keywords in filenames that indicate API spec documents.
_API_SPEC_KEYWORDS: frozenset[str] = frozenset(
    {"openapi", "swagger", "api-spec", "api_spec", "asyncapi"}
)

# Keywords in filenames / path parts that indicate architecture docs.
_ARCH_DOC_KEYWORDS: frozenset[str] = frozenset(
    {"readme", "architecture", "design", "overview", "system", "contributing"}
)

# Max file size to extract (keep prompts manageable).
_MAX_FILE_BYTES = 80 * 1024       # 80 KB per file
_MAX_TOTAL_FILES = 40             # total files per clone

# MIME type mapping used when creating ProjectDocument records.
_EXT_TO_MIME: dict[str, str] = {
    ".py":    "text/x-python",
    ".ts":    "text/typescript",
    ".tsx":   "text/typescript",
    ".js":    "text/javascript",
    ".jsx":   "text/javascript",
    ".go":    "text/x-go",
    ".java":  "text/x-java",
    ".cs":    "text/x-csharp",
    ".rb":    "text/x-ruby",
    ".rs":    "text/x-rust",
    ".yaml":  "text/yaml",
    ".yml":   "text/yaml",
    ".json":  "application/json",
    ".md":    "text/markdown",
    ".txt":   "text/plain",
    ".tf":    "text/x-terraform",
    ".tfvars":"text/x-terraform",
    ".toml":  "text/x-toml",
    ".sh":    "text/x-shellscript",
    ".bash":  "text/x-shellscript",
    ".sql":   "text/x-sql",
    ".html":  "text/html",
    ".css":   "text/css",
}
_DEFAULT_MIME = "text/plain"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class GitServiceError(Exception):
    """Raised when a git operation fails."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def fetch_repository(
    repo_url: str,
    branch: str,
    dest_dir: Path,
    access_token: str | None = None,
    commit_hash: str | None = None,
) -> None:
    """Clone the repository if dest_dir is empty, otherwise pull latest.

    Uses a shallow clone (depth=1) to keep network usage low.
    Raises GitServiceError if git is unavailable or the operation fails.
    """
    if not shutil.which("git"):
        raise GitServiceError(
            "git is not installed or not on PATH — cannot fetch repository code"
        )

    auth_url = _inject_token(repo_url, access_token)

    if (dest_dir / ".git").exists():
        _pull(dest_dir, branch)
    else:
        _clone(auth_url, branch, dest_dir)

    if commit_hash:
        _checkout_commit(dest_dir, commit_hash)


def extract_code_files(repo_dir: Path) -> list[dict[str, Any]]:
    """Walk the repository and return relevant files for analysis.

    Each entry contains:
      - relative_path: str  (e.g. "src/auth/service.py")
      - filename: str       (e.g. "service.py")
      - content: str        (UTF-8 text)
      - size: int           (bytes)
      - tag: str            (document tag for ingestion — e.g. "SAST", "Architecture")
      - mime_type: str      (MIME type for ProjectDocument.type)
    """
    extracted: list[dict[str, Any]] = []

    for file_path in sorted(repo_dir.rglob("*")):
        if len(extracted) >= _MAX_TOTAL_FILES:
            break
        if not file_path.is_file():
            continue

        relative = file_path.relative_to(repo_dir)

        # Skip excluded directories (check every path segment except the filename)
        if any(part.lower() in _SKIP_DIRS for part in relative.parts[:-1]):
            continue

        ext = file_path.suffix.lower()
        name_lower = file_path.name.lower()

        # Bare filenames with no extension (Dockerfile etc.)
        bare_match = (not ext) and (name_lower in _INCLUDE_BARE_NAMES)

        if not (ext in _INCLUDED_EXTENSIONS or bare_match):
            continue

        if file_path.stat().st_size > _MAX_FILE_BYTES:
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace").strip()
        except Exception:
            continue

        if not content:
            continue

        extracted.append(
            {
                "relative_path": str(relative).replace("\\", "/"),
                "filename": file_path.name,
                "content": content,
                "size": len(content.encode("utf-8")),
                "tag": _infer_tag(relative, ext, name_lower),
                "mime_type": _EXT_TO_MIME.get(ext, _DEFAULT_MIME),
            }
        )

    return extracted


def cleanup_repository(repo_dir: Path) -> None:
    """Remove the cloned repository directory."""
    if repo_dir.exists():
        shutil.rmtree(repo_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _clone(auth_url: str, branch: str, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", branch, auth_url, str(dest_dir)],
        capture_output=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise GitServiceError(
            f"git clone failed (branch={branch}): {result.stderr.decode(errors='replace')[:400]}"
        )


def _pull(repo_dir: Path, branch: str) -> None:
    fetch = subprocess.run(
        ["git", "fetch", "--depth", "1", "origin", branch],
        cwd=str(repo_dir),
        capture_output=True,
        timeout=60,
    )
    if fetch.returncode != 0:
        raise GitServiceError(
            f"git fetch failed: {fetch.stderr.decode(errors='replace')[:400]}"
        )
    subprocess.run(
        ["git", "reset", "--hard", f"origin/{branch}"],
        cwd=str(repo_dir),
        capture_output=True,
        timeout=30,
    )


def _checkout_commit(repo_dir: Path, commit_hash: str) -> None:
    normalized = commit_hash.strip()
    if not normalized:
        return
    fetch = subprocess.run(
        ["git", "fetch", "--depth", "1", "origin", normalized],
        cwd=str(repo_dir),
        capture_output=True,
        timeout=60,
    )
    if fetch.returncode != 0:
        # The commit may already be present from the branch fetch.
        rev_parse = subprocess.run(
            ["git", "rev-parse", "--verify", normalized],
            cwd=str(repo_dir),
            capture_output=True,
            timeout=30,
        )
        if rev_parse.returncode != 0:
            raise GitServiceError(
                f"git fetch commit failed: {fetch.stderr.decode(errors='replace')[:400]}"
            )

    checkout = subprocess.run(
        ["git", "checkout", "--detach", normalized],
        cwd=str(repo_dir),
        capture_output=True,
        timeout=30,
    )
    if checkout.returncode != 0:
        raise GitServiceError(
            f"git checkout commit failed: {checkout.stderr.decode(errors='replace')[:400]}"
        )


def _inject_token(repo_url: str, access_token: str | None) -> str:
    """Embed a personal access token into an HTTPS clone URL."""
    if not access_token or not repo_url.startswith("https://"):
        return repo_url
    return repo_url.replace("https://", f"https://x-access-token:{access_token}@", 1)


def _infer_tag(relative_path: Path, ext: str, name_lower: str) -> str:
    """Map a file to the most appropriate document tag for ingestion.

    Tags and their ingestion category:
      "SAST"         → evidence_by_category["sast"]   — source code for vulnerability grounding
      "Architecture" → evidence_by_category["architecture"] — structure / infra / docs
      "API Spec"     → evidence_by_category["manual_review"] — API surface
    """
    parts_lower = {p.lower() for p in relative_path.parts}

    # API specification files
    if any(kw in name_lower for kw in _API_SPEC_KEYWORDS):
        return "API Spec"

    # Architecture documentation: README, design docs
    if ext in {".md", ".txt"}:
        for kw in _ARCH_DOC_KEYWORDS:
            if kw in name_lower:
                return "Architecture"
        return "Architecture"

    # Infrastructure and configuration files
    if ext in {".yaml", ".yml", ".tf", ".tfvars", ".toml", ".ini"}:
        return "Architecture"
    if name_lower in _INCLUDE_BARE_NAMES:
        return "Architecture"

    # JSON config files (package.json, tsconfig, docker-compose, etc.)
    if ext == ".json":
        for kw in ("package", "tsconfig", "docker-compose", "compose", "config"):
            if kw in name_lower:
                return "Architecture"
        return "Architecture"

    # Source code → SAST so the parsing engine applies component mapping
    return "SAST"
