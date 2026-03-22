"""Secret scanner for detecting leaked secrets in files."""

from __future__ import annotations

import os
import re
from typing import Optional

from env_guard.models import (
    SECRET_VALUE_PATTERNS,
    EnvIssue,
    IssueType,
    SecretFinding,
    Severity,
)

# File extensions to scan for secrets
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".rs", ".c", ".cpp", ".h", ".cs", ".swift", ".kt", ".scala",
    ".yml", ".yaml", ".json", ".toml", ".xml", ".cfg", ".ini", ".conf",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
    ".env", ".env.local", ".env.production", ".env.staging",
    ".tf", ".tfvars", ".hcl",
    ".dockerfile", ".docker-compose.yml",
    ".md", ".txt", ".log",
}

# Directories to skip
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    "dist", "build", ".eggs", ".tox", ".mypy_cache",
    ".pytest_cache", "htmlcov", ".coverage", "vendor",
    ".next", ".nuxt", "target", "bin", "obj",
}

# Files to skip
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "Pipfile.lock", "poetry.lock",
    "Cargo.lock", "go.sum", "composer.lock",
}

# Patterns for finding hardcoded secrets in source code
SOURCE_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Hardcoded Password", re.compile(
        r"""(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{4,})['"]""", re.IGNORECASE
    )),
    ("Hardcoded API Key", re.compile(
        r"""(?:api[_-]?key|apikey)\s*[=:]\s*['"]([^'"]{8,})['"]""", re.IGNORECASE
    )),
    ("Hardcoded Secret", re.compile(
        r"""(?:secret|token)\s*[=:]\s*['"]([^'"]{8,})['"]""", re.IGNORECASE
    )),
    ("Hardcoded Auth", re.compile(
        r"""(?:auth|authorization)\s*[=:]\s*['"](?:Bearer |Basic )?([^'"]{8,})['"]""", re.IGNORECASE
    )),
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub Token", re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}")),
    ("Slack Token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----")),
    ("Connection String", re.compile(
        r"(?:mongodb|postgres|mysql|redis|amqp)://[^\s'\"]{10,}"
    )),
]


def scan_file_for_secrets(file_path: str, root: str = "") -> list[SecretFinding]:
    """Scan a single file for hardcoded secrets."""
    findings = []

    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        return findings

    rel_path = os.path.relpath(file_path, root) if root else file_path

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        for pattern_name, pattern in SOURCE_SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                # Extract the key name context
                key = _extract_key_from_line(line)
                value_preview = _mask_value(match.group(0)[:50])

                findings.append(SecretFinding(
                    file_path=rel_path,
                    line_number=i,
                    key=key or pattern_name,
                    pattern_name=pattern_name,
                    value_preview=value_preview,
                ))
                break  # One finding per line

    return findings


def scan_directory_for_secrets(
    root: str,
    extensions: Optional[set[str]] = None,
    max_file_size: int = 1024 * 1024,  # 1MB
) -> list[SecretFinding]:
    """Scan a directory tree for hardcoded secrets."""
    findings = []
    exts = extensions or SCANNABLE_EXTENSIONS

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            if filename in SKIP_FILES:
                continue

            _, ext = os.path.splitext(filename)
            if ext not in exts and not filename.startswith(".env"):
                continue

            file_path = os.path.join(dirpath, filename)

            # Skip large files
            try:
                if os.path.getsize(file_path) > max_file_size:
                    continue
            except OSError:
                continue

            findings.extend(scan_file_for_secrets(file_path, root))

    return findings


def scan_env_values(env_file_or_dict) -> list[SecretFinding]:
    """Scan environment variable values for known secret patterns."""
    findings = []

    # Accept EnvFile or dict
    if hasattr(env_file_or_dict, "variables"):
        items = [(k, v.value) for k, v in env_file_or_dict.variables.items()]
    else:
        items = list(env_file_or_dict.items())

    for key, value in items:
        if not value or len(value) < 8:
            continue

        for pattern_name, pattern in SECRET_VALUE_PATTERNS:
            if pattern.search(value):
                findings.append(SecretFinding(
                    file_path="environment",
                    line_number=0,
                    key=key,
                    pattern_name=pattern_name,
                    value_preview=_mask_value(value[:30]),
                ))
                break

    return findings


def check_gitignore_for_env(root: str) -> list[EnvIssue]:
    """Check if .env is properly gitignored."""
    issues = []

    # If no .env file exists, nothing to worry about
    env_path = os.path.join(root, ".env")
    if not os.path.exists(env_path):
        return issues

    gitignore_path = os.path.join(root, ".gitignore")

    if not os.path.exists(gitignore_path):
        issues.append(EnvIssue(
            type=IssueType.SECRET_IN_FILE,
            severity=Severity.HIGH,
            key=".gitignore",
            message="No .gitignore found — .env files may be committed",
            suggestion="Create .gitignore with '.env' entry",
        ))
        return issues

    try:
        with open(gitignore_path, encoding="utf-8") as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return issues

    env_patterns = [".env", "*.env", ".env.*", ".env.local"]
    has_env_ignore = any(
        re.search(rf"^{re.escape(p)}(\s|$)", content, re.MULTILINE)
        for p in env_patterns
    )

    if not has_env_ignore:
        issues.append(EnvIssue(
            type=IssueType.SECRET_IN_FILE,
            severity=Severity.HIGH,
            key=".env",
            message=".env is not listed in .gitignore — secrets may be committed",
            file_path=".gitignore",
            suggestion="Add '.env' to .gitignore",
        ))

    return issues


def _extract_key_from_line(line: str) -> str:
    """Try to extract the variable/key name from a line."""
    # Match patterns like: key = "value", key: "value", KEY="value"
    match = re.match(r"""^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*""", line)
    if match:
        return match.group(1)

    # Match dict/object patterns: "key": "value"
    match = re.match(r"""^\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]""", line)
    if match:
        return match.group(1)

    return ""


def _mask_value(value: str) -> str:
    """Mask a value for safe display."""
    if len(value) <= 8:
        return "***"
    return value[:4] + "****" + value[-4:]
