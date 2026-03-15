"""Tests for env_guard.validators."""

from __future__ import annotations

import pytest

from env_guard.models import (
    EnvFile,
    EnvIssue,
    EnvVar,
    IssueType,
    Severity,
    ValidationRule,
    VarType,
)
from env_guard.parser import parse_env_file
from env_guard.validators import validate_env_file


def make_env(variables: dict[str, str], path: str = ".env") -> EnvFile:
    """Helper to build EnvFile from dict."""
    vars_map = {}
    for i, (k, v) in enumerate(variables.items(), 1):
        vars_map[k] = EnvVar(key=k, value=v, line_number=i, file_path=path)
    return EnvFile(path=path, variables=vars_map)


class TestValidateBasic:
    def test_no_issues_on_valid_file(self):
        env = make_env({"APP_NAME": "test", "PORT": "8080"})
        issues = validate_env_file(env)
        # No rules = only basic checks
        critical = [i for i in issues if i.severity == Severity.CRITICAL]
        assert len(critical) == 0

    def test_empty_value_warning(self):
        env = make_env({"APP_NAME": "", "PORT": "8080"})
        issues = validate_env_file(env)
        empty = [i for i in issues if i.type == IssueType.EMPTY_VALUE]
        assert len(empty) >= 1

    def test_naming_convention(self):
        env = make_env({"appName": "test"})
        issues = validate_env_file(env)
        naming = [i for i in issues if i.type == IssueType.NAMING_CONVENTION]
        assert len(naming) >= 1

    def test_weak_secret_detection(self):
        env = make_env({"SECRET_KEY": "password"})
        issues = validate_env_file(env)
        weak = [i for i in issues if i.type == IssueType.WEAK_SECRET]
        assert len(weak) >= 1


class TestValidateWithRules:
    def test_missing_required(self):
        env = make_env({"APP_NAME": "test"})
        rules = [
            ValidationRule(key="APP_NAME", required=True),
            ValidationRule(key="DB_URL", required=True),
        ]
        issues = validate_env_file(env, rules)
        missing = [i for i in issues if i.type == IssueType.MISSING_REQUIRED]
        assert len(missing) == 1
        assert missing[0].key == "DB_URL"

    def test_missing_optional_no_issue(self):
        env = make_env({"APP_NAME": "test"})
        rules = [
            ValidationRule(key="APP_NAME", required=True),
            ValidationRule(key="DEBUG", required=False),
        ]
        issues = validate_env_file(env, rules)
        missing = [i for i in issues if i.type == IssueType.MISSING_REQUIRED]
        assert len(missing) == 0

    def test_type_integer(self):
        env = make_env({"COUNT": "abc"})
        rules = [ValidationRule(key="COUNT", var_type=VarType.INTEGER)]
        issues = validate_env_file(env, rules)
        type_issues = [i for i in issues if i.type == IssueType.TYPE_MISMATCH]
        assert len(type_issues) >= 1

    def test_type_integer_valid(self):
        env = make_env({"COUNT": "42"})
        rules = [ValidationRule(key="COUNT", var_type=VarType.INTEGER)]
        issues = validate_env_file(env, rules)
        type_issues = [i for i in issues if i.type == IssueType.TYPE_MISMATCH]
        assert len(type_issues) == 0

    def test_type_boolean(self):
        env = make_env({"DEBUG": "maybe"})
        rules = [ValidationRule(key="DEBUG", var_type=VarType.BOOLEAN)]
        issues = validate_env_file(env, rules)
        type_issues = [i for i in issues if i.type == IssueType.TYPE_MISMATCH]
        assert len(type_issues) >= 1

    def test_type_boolean_valid(self):
        env = make_env({"DEBUG": "true"})
        rules = [ValidationRule(key="DEBUG", var_type=VarType.BOOLEAN)]
        issues = validate_env_file(env, rules)
        type_issues = [i for i in issues if i.type == IssueType.TYPE_MISMATCH]
        assert len(type_issues) == 0

    def test_type_url(self):
        env = make_env({"SITE": "not-a-url"})
        rules = [ValidationRule(key="SITE", var_type=VarType.URL)]
        issues = validate_env_file(env, rules)
        type_issues = [i for i in issues if i.type == IssueType.TYPE_MISMATCH]
        assert len(type_issues) >= 1

    def test_type_url_valid(self):
        env = make_env({"SITE": "https://example.com"})
        rules = [ValidationRule(key="SITE", var_type=VarType.URL)]
        issues = validate_env_file(env, rules)
        type_issues = [i for i in issues if i.type == IssueType.TYPE_MISMATCH]
        assert len(type_issues) == 0

    def test_type_email(self):
        env = make_env({"MAIL": "not-email"})
        rules = [ValidationRule(key="MAIL", var_type=VarType.EMAIL)]
        issues = validate_env_file(env, rules)
        type_issues = [i for i in issues if i.type == IssueType.TYPE_MISMATCH]
        assert len(type_issues) >= 1

    def test_type_email_valid(self):
        env = make_env({"MAIL": "user@example.com"})
        rules = [ValidationRule(key="MAIL", var_type=VarType.EMAIL)]
        issues = validate_env_file(env, rules)
        type_issues = [i for i in issues if i.type == IssueType.TYPE_MISMATCH]
        assert len(type_issues) == 0

    def test_type_port(self):
        env = make_env({"PORT": "99999"})
        rules = [ValidationRule(key="PORT", var_type=VarType.PORT)]
        issues = validate_env_file(env, rules)
        type_issues = [i for i in issues if i.type == IssueType.TYPE_MISMATCH]
        assert len(type_issues) >= 1

    def test_type_port_valid(self):
        env = make_env({"PORT": "8080"})
        rules = [ValidationRule(key="PORT", var_type=VarType.PORT)]
        issues = validate_env_file(env, rules)
        type_issues = [i for i in issues if i.type == IssueType.TYPE_MISMATCH]
        assert len(type_issues) == 0

    def test_type_json(self):
        env = make_env({"DATA": "not json"})
        rules = [ValidationRule(key="DATA", var_type=VarType.JSON)]
        issues = validate_env_file(env, rules)
        type_issues = [i for i in issues if i.type == IssueType.TYPE_MISMATCH]
        assert len(type_issues) >= 1

    def test_type_json_valid(self):
        env = make_env({"DATA": '{"key": "value"}'})
        rules = [ValidationRule(key="DATA", var_type=VarType.JSON)]
        issues = validate_env_file(env, rules)
        type_issues = [i for i in issues if i.type == IssueType.TYPE_MISMATCH]
        assert len(type_issues) == 0

    def test_type_float(self):
        env = make_env({"RATE": "abc"})
        rules = [ValidationRule(key="RATE", var_type=VarType.FLOAT)]
        issues = validate_env_file(env, rules)
        type_issues = [i for i in issues if i.type == IssueType.TYPE_MISMATCH]
        assert len(type_issues) >= 1

    def test_type_float_valid(self):
        env = make_env({"RATE": "3.14"})
        rules = [ValidationRule(key="RATE", var_type=VarType.FLOAT)]
        issues = validate_env_file(env, rules)
        type_issues = [i for i in issues if i.type == IssueType.TYPE_MISMATCH]
        assert len(type_issues) == 0

    def test_allowed_values(self):
        env = make_env({"ENV": "banana"})
        rules = [ValidationRule(key="ENV", var_type=VarType.ENUM, allowed_values=["dev", "prod"])]
        issues = validate_env_file(env, rules)
        type_issues = [i for i in issues if i.type == IssueType.TYPE_MISMATCH]
        assert len(type_issues) >= 1

    def test_allowed_values_valid(self):
        env = make_env({"ENV": "dev"})
        rules = [ValidationRule(key="ENV", var_type=VarType.ENUM, allowed_values=["dev", "prod"])]
        issues = validate_env_file(env, rules)
        type_issues = [i for i in issues if i.type == IssueType.TYPE_MISMATCH]
        assert len(type_issues) == 0

    def test_min_length(self):
        env = make_env({"TOKEN": "abc"})
        rules = [ValidationRule(key="TOKEN", min_length=10)]
        issues = validate_env_file(env, rules)
        format_issues = [i for i in issues if i.type == IssueType.INVALID_FORMAT]
        assert len(format_issues) >= 1

    def test_max_length(self):
        env = make_env({"CODE": "ABCDEFGHIJ"})
        rules = [ValidationRule(key="CODE", max_length=5)]
        issues = validate_env_file(env, rules)
        format_issues = [i for i in issues if i.type == IssueType.INVALID_FORMAT]
        assert len(format_issues) >= 1

    def test_pattern(self):
        env = make_env({"CODE": "abc"})
        rules = [ValidationRule(key="CODE", pattern=r"^[A-Z]{3}$")]
        issues = validate_env_file(env, rules)
        format_issues = [i for i in issues if i.type == IssueType.INVALID_FORMAT]
        assert len(format_issues) >= 1

    def test_pattern_valid(self):
        env = make_env({"CODE": "ABC"})
        rules = [ValidationRule(key="CODE", pattern=r"^[A-Z]{3}$")]
        issues = validate_env_file(env, rules)
        format_issues = [i for i in issues if i.type == IssueType.INVALID_FORMAT]
        assert len(format_issues) == 0


class TestValidateWithFile:
    def test_sample_env(self, sample_env):
        parsed = parse_env_file(str(sample_env))
        issues = validate_env_file(parsed)
        # Should detect empty variable and possibly weak secret
        assert isinstance(issues, list)

    def test_with_schema(self, sample_env, sample_schema):
        parsed = parse_env_file(str(sample_env))
        from env_guard.parser import parse_schema_file
        rules = parse_schema_file(str(sample_schema))
        issues = validate_env_file(parsed, rules)
        assert isinstance(issues, list)
