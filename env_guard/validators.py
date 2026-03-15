"""Validators for environment variables."""

from __future__ import annotations

import json
import re
from typing import Optional

from env_guard.models import (
    EnvFile,
    EnvIssue,
    IssueType,
    Severity,
    ValidationRule,
    VarType,
    follows_naming_convention,
    is_secret_key,
    is_weak_secret,
)


def validate_env_file(
    env_file: EnvFile,
    rules: Optional[list[ValidationRule]] = None,
    check_naming: bool = True,
    check_empty: bool = True,
    check_duplicates: bool = True,
    check_secrets: bool = True,
) -> list[EnvIssue]:
    """Validate an env file and return found issues."""
    issues: list[EnvIssue] = []

    # Schema-based validation
    if rules:
        issues.extend(_validate_rules(env_file, rules))

    # Empty value check
    if check_empty:
        for key, var in env_file.variables.items():
            if var.is_empty and not _is_optional_in_rules(key, rules):
                issues.append(EnvIssue(
                    type=IssueType.EMPTY_VALUE,
                    severity=Severity.MEDIUM if is_secret_key(key) else Severity.LOW,
                    key=key,
                    message=f"Variable '{key}' has an empty value",
                    file_path=env_file.path,
                    line_number=var.line_number,
                    suggestion=f"Set a value for {key} or mark as optional in schema",
                ))

    # Naming convention check
    if check_naming:
        for key, var in env_file.variables.items():
            if not follows_naming_convention(key):
                issues.append(EnvIssue(
                    type=IssueType.NAMING_CONVENTION,
                    severity=Severity.INFO,
                    key=key,
                    message=f"'{key}' doesn't follow UPPER_SNAKE_CASE convention",
                    file_path=env_file.path,
                    line_number=var.line_number,
                    suggestion=f"Rename to {key.upper().replace('-', '_').replace('.', '_')}",
                ))

    # Weak secret check
    if check_secrets:
        for key, var in env_file.variables.items():
            if is_secret_key(key) and not var.is_empty and is_weak_secret(var.value):
                issues.append(EnvIssue(
                    type=IssueType.WEAK_SECRET,
                    severity=Severity.HIGH,
                    key=key,
                    message=f"Secret '{key}' appears to have a weak/default value",
                    file_path=env_file.path,
                    line_number=var.line_number,
                    suggestion="Use a strong, randomly generated value (32+ chars)",
                ))

    # Sort by severity
    issues.sort(key=lambda i: i.severity.priority)
    return issues


def _validate_rules(env_file: EnvFile, rules: list[ValidationRule]) -> list[EnvIssue]:
    """Validate env file against schema rules."""
    issues = []

    for rule in rules:
        var = env_file.variables.get(rule.key)

        # Missing required variable
        if var is None:
            if rule.required:
                issues.append(EnvIssue(
                    type=IssueType.MISSING_REQUIRED,
                    severity=Severity.CRITICAL,
                    key=rule.key,
                    message=f"Required variable '{rule.key}' is missing",
                    file_path=env_file.path,
                    suggestion=f"Add {rule.key}= to {env_file.path}" + (
                        f" ({rule.description})" if rule.description else ""
                    ),
                ))
            continue

        # Skip further checks if empty (handled elsewhere)
        if var.is_empty:
            continue

        # Type validation
        type_issue = _validate_type(var.value, rule)
        if type_issue:
            issues.append(EnvIssue(
                type=IssueType.TYPE_MISMATCH,
                severity=Severity.MEDIUM,
                key=rule.key,
                message=type_issue,
                file_path=env_file.path,
                line_number=var.line_number,
                suggestion=f"Expected type: {rule.var_type.value}",
            ))

        # Pattern validation
        if rule.pattern:
            if not re.match(rule.pattern, var.value):
                issues.append(EnvIssue(
                    type=IssueType.INVALID_FORMAT,
                    severity=Severity.MEDIUM,
                    key=rule.key,
                    message=f"Value doesn't match pattern: {rule.pattern}",
                    file_path=env_file.path,
                    line_number=var.line_number,
                ))

        # Length validation
        if rule.min_length and len(var.value) < rule.min_length:
            issues.append(EnvIssue(
                type=IssueType.INVALID_FORMAT,
                severity=Severity.MEDIUM,
                key=rule.key,
                message=f"Value too short (min {rule.min_length} chars)",
                file_path=env_file.path,
                line_number=var.line_number,
            ))

        if rule.max_length and len(var.value) > rule.max_length:
            issues.append(EnvIssue(
                type=IssueType.INVALID_FORMAT,
                severity=Severity.MEDIUM,
                key=rule.key,
                message=f"Value too long (max {rule.max_length} chars)",
                file_path=env_file.path,
                line_number=var.line_number,
            ))

        # Allowed values
        if rule.allowed_values and var.value not in rule.allowed_values:
            issues.append(EnvIssue(
                type=IssueType.INVALID_FORMAT,
                severity=Severity.MEDIUM,
                key=rule.key,
                message=f"Value '{var.value}' not in allowed values: {rule.allowed_values}",
                file_path=env_file.path,
                line_number=var.line_number,
            ))

    return issues


def _validate_type(value: str, rule: ValidationRule) -> Optional[str]:
    """Validate a value against its expected type. Returns error message or None."""
    vtype = rule.var_type

    if vtype == VarType.INTEGER:
        try:
            int(value)
        except ValueError:
            return f"'{value}' is not a valid integer"

    elif vtype == VarType.FLOAT:
        try:
            float(value)
        except ValueError:
            return f"'{value}' is not a valid float"

    elif vtype == VarType.BOOLEAN:
        if value.lower() not in ("true", "false", "yes", "no", "1", "0", "on", "off"):
            return f"'{value}' is not a valid boolean"

    elif vtype == VarType.URL:
        if not re.match(r"^https?://", value):
            return f"'{value}' is not a valid URL (must start with http:// or https://)"

    elif vtype == VarType.EMAIL:
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", value):
            return f"'{value}' is not a valid email"

    elif vtype == VarType.PORT:
        try:
            port = int(value)
            if port < 1 or port > 65535:
                return f"Port {port} is out of range (1-65535)"
        except ValueError:
            return f"'{value}' is not a valid port number"

    elif vtype == VarType.JSON:
        try:
            json.loads(value)
        except json.JSONDecodeError:
            return f"'{value}' is not valid JSON"

    elif vtype == VarType.ENUM:
        if rule.allowed_values and value not in rule.allowed_values:
            return f"'{value}' not in allowed values: {rule.allowed_values}"

    return None


def _is_optional_in_rules(key: str, rules: Optional[list[ValidationRule]]) -> bool:
    """Check if a key is marked optional in the rules."""
    if not rules:
        return False
    for rule in rules:
        if rule.key == key and not rule.required:
            return True
    return False
