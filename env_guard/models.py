"""Data models for env-guard."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Issue severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def icon(self) -> str:
        icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪",
        }
        return icons.get(self.value, "⚪")

    @property
    def priority(self) -> int:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return order.get(self.value, 99)


class IssueType(Enum):
    """Types of environment issues."""
    MISSING_REQUIRED = "missing_required"
    EMPTY_VALUE = "empty_value"
    INVALID_FORMAT = "invalid_format"
    SECRET_EXPOSED = "secret_exposed"
    SECRET_IN_FILE = "secret_in_file"
    WEAK_SECRET = "weak_secret"
    DUPLICATE_KEY = "duplicate_key"
    UNUSED_VARIABLE = "unused_variable"
    MISSING_IN_EXAMPLE = "missing_in_example"
    EXTRA_IN_EXAMPLE = "extra_in_example"
    TYPE_MISMATCH = "type_mismatch"
    NAMING_CONVENTION = "naming_convention"

    @property
    def label(self) -> str:
        labels = {
            "missing_required": "Missing Required Variable",
            "empty_value": "Empty Value",
            "invalid_format": "Invalid Format",
            "secret_exposed": "Secret Exposed in Code",
            "secret_in_file": "Secret Committed to File",
            "weak_secret": "Weak Secret Value",
            "duplicate_key": "Duplicate Key",
            "unused_variable": "Unused Variable",
            "missing_in_example": "Missing in Example",
            "extra_in_example": "Extra in Example",
            "type_mismatch": "Type Mismatch",
            "naming_convention": "Naming Convention Violation",
        }
        return labels.get(self.value, self.value)


class VarType(Enum):
    """Expected variable value types."""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    URL = "url"
    EMAIL = "email"
    PORT = "port"
    PATH = "path"
    JSON = "json"
    ENUM = "enum"


@dataclass
class EnvVar:
    """A parsed environment variable."""
    key: str
    value: str
    line_number: int = 0
    file_path: str = ""
    comment: str = ""
    is_commented: bool = False
    is_empty: bool = False

    def __post_init__(self):
        self.is_empty = self.value.strip() == ""


@dataclass
class EnvIssue:
    """A detected issue with an environment variable."""
    type: IssueType
    severity: Severity
    key: str
    message: str
    file_path: str = ""
    line_number: int = 0
    suggestion: str = ""

    @property
    def display(self) -> str:
        loc = f"{self.file_path}:{self.line_number}" if self.line_number else self.file_path
        return f"[{self.severity.value.upper()}] {self.key}: {self.message}" + (f" ({loc})" if loc else "")


@dataclass
class ValidationRule:
    """A rule for validating an environment variable."""
    key: str
    required: bool = True
    var_type: VarType = VarType.STRING
    pattern: Optional[str] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    allowed_values: Optional[list[str]] = None
    default: Optional[str] = None
    description: str = ""
    secret: bool = False


@dataclass
class EnvFile:
    """Parsed .env file."""
    path: str
    variables: dict[str, EnvVar] = field(default_factory=dict)
    comments: list[str] = field(default_factory=list)
    raw_lines: list[str] = field(default_factory=list)

    @property
    def keys(self) -> set[str]:
        return set(self.variables.keys())

    @property
    def count(self) -> int:
        return len(self.variables)

    @property
    def empty_count(self) -> int:
        return sum(1 for v in self.variables.values() if v.is_empty)

    @property
    def secret_count(self) -> int:
        return sum(1 for k in self.variables if is_secret_key(k))


@dataclass
class EnvDiff:
    """Difference between two env files."""
    source_path: str
    target_path: str
    missing_in_target: list[str] = field(default_factory=list)
    missing_in_source: list[str] = field(default_factory=list)
    different_values: list[tuple[str, str, str]] = field(default_factory=list)
    same: list[str] = field(default_factory=list)

    @property
    def has_differences(self) -> bool:
        return bool(self.missing_in_target or self.missing_in_source or self.different_values)

    @property
    def total_keys(self) -> int:
        return len(set(self.missing_in_target + self.missing_in_source +
                       [d[0] for d in self.different_values] + self.same))


@dataclass
class SecretFinding:
    """A secret detected in a file."""
    file_path: str
    line_number: int
    key: str
    pattern_name: str
    value_preview: str
    severity: Severity = Severity.CRITICAL

    @property
    def display(self) -> str:
        return f"{self.file_path}:{self.line_number} — {self.pattern_name}: {self.key}"


@dataclass
class ScanResult:
    """Result of an environment scan."""
    files_scanned: list[str] = field(default_factory=list)
    env_files: list[EnvFile] = field(default_factory=list)
    issues: list[EnvIssue] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    total_variables: int = 0

    @property
    def total_issues(self) -> int:
        return len(self.issues) + len(self.secrets)

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.CRITICAL) + len(self.secrets)

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.HIGH)

    @property
    def has_critical(self) -> bool:
        return self.critical_count > 0

    @property
    def health_score(self) -> float:
        if self.total_variables == 0:
            return 100.0
        issue_weight = (
            self.critical_count * 10
            + self.high_count * 5
            + sum(1 for i in self.issues if i.severity == Severity.MEDIUM) * 2
            + sum(1 for i in self.issues if i.severity == Severity.LOW)
        )
        score = max(0, 100 - (issue_weight / max(self.total_variables, 1)) * 100)
        return round(score, 1)

    @property
    def grade(self) -> str:
        s = self.health_score
        if s >= 95:
            return "A+"
        elif s >= 90:
            return "A"
        elif s >= 80:
            return "B"
        elif s >= 70:
            return "C"
        elif s >= 60:
            return "D"
        else:
            return "F"


# ── Secret Detection Patterns ──────────────────────────────────────

SECRET_KEY_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd)"),
    re.compile(r"(?i)(secret|token|key|api_key|apikey)"),
    re.compile(r"(?i)(credential|auth)"),
    re.compile(r"(?i)(private|access).*(?:key|token)"),
    re.compile(r"(?i)(aws|azure|gcp|google).*(?:key|secret|token)"),
    re.compile(r"(?i)(database|db).*(?:password|pass|pwd)"),
    re.compile(r"(?i)(jwt|bearer|oauth)"),
    re.compile(r"(?i)(ssh|ssl|tls).*(?:key|cert|certificate)"),
    re.compile(r"(?i)(stripe|twilio|sendgrid|mailgun)"),
    re.compile(r"(?i)(encryption|decrypt|encrypt).*(?:key)"),
]

SECRET_VALUE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"[A-Za-z0-9/+=]{40}")),
    ("GitHub Token", re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}")),
    ("GitHub PAT", re.compile(r"github_pat_[A-Za-z0-9_]{82}")),
    ("Slack Token", re.compile(r"xox[baprs]-[A-Za-z0-9-]+")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----")),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+")),
    ("Generic API Key", re.compile(r"[A-Za-z0-9]{32,64}")),
    ("Base64 Encoded", re.compile(r"[A-Za-z0-9+/]{40,}={0,2}$")),
    ("Hex Encoded Secret", re.compile(r"[0-9a-fA-F]{32,64}")),
    ("Connection String", re.compile(r"(?:mongodb|postgres|mysql|redis)://[^\s]+")),
]

WEAK_SECRET_PATTERNS = [
    re.compile(r"^(password|secret|admin|root|test|demo|example|changeme|12345|qwerty)$", re.IGNORECASE),
    re.compile(r"^(.)\1+$"),  # All same character
    re.compile(r"^[a-z]{1,6}$"),  # Too short lowercase only
    re.compile(r"^[0-9]{1,6}$"),  # Too short numbers only
]

# Naming convention pattern (UPPER_SNAKE_CASE)
NAMING_PATTERN = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$")


def is_secret_key(key: str) -> bool:
    """Check if a variable key name looks like it holds a secret."""
    return any(p.search(key) for p in SECRET_KEY_PATTERNS)


def is_weak_secret(value: str) -> bool:
    """Check if a secret value looks weak/default."""
    if len(value) < 8:
        return True
    return any(p.match(value) for p in WEAK_SECRET_PATTERNS)


def follows_naming_convention(key: str) -> bool:
    """Check if a key follows UPPER_SNAKE_CASE convention."""
    return bool(NAMING_PATTERN.match(key))
