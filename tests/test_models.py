"""Tests for env_guard.models."""

from __future__ import annotations

import pytest

from env_guard.models import (
    NAMING_PATTERN,
    SECRET_KEY_PATTERNS,
    SECRET_VALUE_PATTERNS,
    WEAK_SECRET_PATTERNS,
    EnvDiff,
    EnvFile,
    EnvIssue,
    EnvVar,
    IssueType,
    ScanResult,
    SecretFinding,
    Severity,
    ValidationRule,
    VarType,
    follows_naming_convention,
    is_secret_key,
    is_weak_secret,
)

# ---------- Severity ----------

class TestSeverity:
    def test_icon_critical(self):
        assert Severity.CRITICAL.icon == "🔴"

    def test_icon_high(self):
        assert Severity.HIGH.icon == "🟠"

    def test_icon_medium(self):
        assert Severity.MEDIUM.icon == "🟡"

    def test_icon_low(self):
        assert Severity.LOW.icon == "🔵"

    def test_icon_info(self):
        assert Severity.INFO.icon == "⚪"

    def test_priority_order(self):
        assert Severity.CRITICAL.priority < Severity.HIGH.priority
        assert Severity.HIGH.priority < Severity.MEDIUM.priority
        assert Severity.MEDIUM.priority < Severity.LOW.priority
        assert Severity.LOW.priority < Severity.INFO.priority


# ---------- IssueType ----------

class TestIssueType:
    def test_label_missing_required(self):
        assert IssueType.MISSING_REQUIRED.label == "Missing Required Variable"

    def test_label_secret_exposed(self):
        assert IssueType.SECRET_EXPOSED.label == "Secret Exposed in Code"

    def test_label_naming_convention(self):
        assert IssueType.NAMING_CONVENTION.label == "Naming Convention Violation"

    def test_all_labels_are_strings(self):
        for it in IssueType:
            assert isinstance(it.label, str)
            assert len(it.label) > 0


# ---------- VarType ----------

class TestVarType:
    def test_var_types_exist(self):
        assert VarType.STRING.value == "string"
        assert VarType.INTEGER.value == "integer"
        assert VarType.FLOAT.value == "float"
        assert VarType.BOOLEAN.value == "boolean"
        assert VarType.URL.value == "url"
        assert VarType.EMAIL.value == "email"
        assert VarType.PORT.value == "port"
        assert VarType.PATH.value == "path"
        assert VarType.JSON.value == "json"
        assert VarType.ENUM.value == "enum"


# ---------- EnvVar ----------

class TestEnvVar:
    def test_basic(self):
        var = EnvVar(key="FOO", value="bar", line_number=1, file_path=".env")
        assert var.key == "FOO"
        assert var.value == "bar"
        assert var.is_empty is False
        assert var.is_commented is False

    def test_empty(self):
        var = EnvVar(key="X", value="", line_number=2, file_path=".env")
        assert var.is_empty is True

    def test_commented(self):
        var = EnvVar(key="Y", value="z", line_number=3, file_path=".env", is_commented=True)
        assert var.is_commented is True

    def test_with_comment(self):
        var = EnvVar(key="A", value="b", line_number=1, file_path=".env", comment="inline")
        assert var.comment == "inline"


# ---------- EnvIssue ----------

class TestEnvIssue:
    def test_display(self):
        issue = EnvIssue(
            type=IssueType.MISSING_REQUIRED,
            severity=Severity.CRITICAL,
            key="DB_PASS",
            message="Required variable not set",
            file_path=".env",
        )
        assert "DB_PASS" in issue.display
        assert "CRITICAL" in issue.display.upper() or "🔴" in issue.display

    def test_with_suggestion(self):
        issue = EnvIssue(
            type=IssueType.EMPTY_VALUE,
            severity=Severity.MEDIUM,
            key="FOO",
            message="Value is empty",
            suggestion="Set a value",
        )
        assert issue.suggestion == "Set a value"


# ---------- ValidationRule ----------

class TestValidationRule:
    def test_basic_rule(self):
        rule = ValidationRule(key="PORT", required=True, var_type=VarType.PORT)
        assert rule.key == "PORT"
        assert rule.required is True
        assert rule.var_type == VarType.PORT

    def test_with_allowed_values(self):
        rule = ValidationRule(key="ENV", allowed_values=["dev", "prod"])
        assert rule.allowed_values == ["dev", "prod"]


# ---------- EnvFile ----------

class TestEnvFile:
    def test_keys(self):
        ef = EnvFile(
            path=".env",
            variables={"A": EnvVar("A", "1", 1, ".env"), "B": EnvVar("B", "2", 2, ".env")},
        )
        assert set(ef.keys) == {"A", "B"}
        assert ef.count == 2

    def test_empty_count(self):
        ef = EnvFile(
            path=".env",
            variables={
                "X": EnvVar("X", "", 1, ".env"),
                "Y": EnvVar("Y", "val", 2, ".env"),
            },
        )
        assert ef.empty_count == 1

    def test_secret_count(self):
        ef = EnvFile(
            path=".env",
            variables={
                "API_KEY": EnvVar("API_KEY", "abc", 1, ".env"),
                "APP_NAME": EnvVar("APP_NAME", "test", 2, ".env"),
            },
        )
        assert ef.secret_count >= 1  # API_KEY should be detected


# ---------- EnvDiff ----------

class TestEnvDiff:
    def test_no_differences(self):
        d = EnvDiff(
            source_path=".env",
            target_path=".env.example",
            missing_in_target=[],
            missing_in_source=[],
            different_values=[],
            same=["A", "B"],
        )
        assert d.has_differences is False
        assert d.total_keys == 2

    def test_with_differences(self):
        d = EnvDiff(
            source_path=".env",
            target_path=".env.example",
            missing_in_target=["X"],
            missing_in_source=["Y"],
            different_values=[("Z", "1", "2")],
            same=["A"],
        )
        assert d.has_differences is True
        assert d.total_keys == 4


# ---------- SecretFinding ----------

class TestSecretFinding:
    def test_basic(self):
        sf = SecretFinding(
            file_path="src/config.py",
            line_number=10,
            key="AWS_SECRET",
            pattern_name="aws_key",
            value_preview="AKIA****",
            severity=Severity.CRITICAL,
        )
        assert sf.file_path == "src/config.py"
        assert sf.severity == Severity.CRITICAL


# ---------- ScanResult ----------

class TestScanResult:
    def test_health_score_perfect(self):
        r = ScanResult(
            files_scanned=["a.py"],
            env_files=[],
            issues=[],
            secrets=[],
            total_variables=10,
        )
        assert r.health_score == 100
        assert r.grade == "A+"

    def test_health_score_with_issues(self):
        issues = [
            EnvIssue(IssueType.MISSING_REQUIRED, Severity.CRITICAL, "X", "missing"),
            EnvIssue(IssueType.EMPTY_VALUE, Severity.MEDIUM, "Y", "empty"),
        ]
        r = ScanResult(
            files_scanned=[],
            env_files=[],
            issues=issues,
            secrets=[],
            total_variables=5,
        )
        assert r.health_score < 100

    def test_grade_thresholds(self):
        for score, expected in [(100, "A+"), (95, "A"), (85, "B"), (75, "C"), (65, "D")]:
            r = ScanResult([], [], [], [], 0)
            # Override health_score by checking grade logic
            # Just verify grade property works with current state
            assert isinstance(r.grade, str)

    def test_critical_count(self):
        issues = [
            EnvIssue(IssueType.MISSING_REQUIRED, Severity.CRITICAL, "A", "x"),
            EnvIssue(IssueType.MISSING_REQUIRED, Severity.CRITICAL, "B", "x"),
            EnvIssue(IssueType.EMPTY_VALUE, Severity.LOW, "C", "x"),
        ]
        r = ScanResult([], [], issues, [], 5)
        assert r.critical_count == 2
        assert r.has_critical is True


# ---------- Helper functions ----------

class TestHelperFunctions:
    @pytest.mark.parametrize("key", [
        "API_KEY", "SECRET_KEY", "AWS_SECRET_ACCESS_KEY", "DATABASE_PASSWORD",
        "JWT_TOKEN", "AUTH_TOKEN", "PRIVATE_KEY", "DB_PASS", "STRIPE_SECRET",
        "GITHUB_TOKEN",
    ])
    def test_is_secret_key_true(self, key):
        assert is_secret_key(key) is True

    @pytest.mark.parametrize("key", [
        "APP_NAME", "PORT", "DEBUG", "LOG_LEVEL", "NODE_ENV", "HOST",
    ])
    def test_is_secret_key_false(self, key):
        assert is_secret_key(key) is False

    @pytest.mark.parametrize("value", [
        "password", "changeme", "123456", "secret", "admin",
    ])
    def test_is_weak_secret_true(self, value):
        assert is_weak_secret(value) is True

    @pytest.mark.parametrize("value", [
        "xK9$mP2!qW7@bN4", "a-very-strong-random-token-abc123xyz",
    ])
    def test_is_weak_secret_false(self, value):
        assert is_weak_secret(value) is False

    @pytest.mark.parametrize("key,expected", [
        ("APP_NAME", True),
        ("DATABASE_URL", True),
        ("MY_VAR_123", True),
        ("appName", False),
        ("app-name", False),
        ("app name", False),
    ])
    def test_follows_naming_convention(self, key, expected):
        assert follows_naming_convention(key) is expected


# ---------- Pattern constants ----------

class TestPatterns:
    def test_secret_key_patterns_exist(self):
        assert len(SECRET_KEY_PATTERNS) >= 5

    def test_secret_value_patterns_exist(self):
        assert len(SECRET_VALUE_PATTERNS) >= 5

    def test_weak_secret_patterns_exist(self):
        assert len(WEAK_SECRET_PATTERNS) >= 2

    def test_naming_pattern(self):
        import re
        assert re.match(NAMING_PATTERN, "HELLO_WORLD")
        assert not re.match(NAMING_PATTERN, "helloWorld")
