"""Tests for env_guard.output (rendering functions)."""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from env_guard.models import (
    EnvDiff,
    EnvFile,
    EnvIssue,
    EnvVar,
    IssueType,
    ScanResult,
    SecretFinding,
    Severity,
)
from env_guard.output import (
    render_diff,
    render_env_file_info,
    render_issues,
    render_scan_result,
    render_secrets,
    render_sync_result,
)


def capture_output(func, *args, **kwargs) -> str:
    """Capture Rich console output."""
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=120)
    # Monkey-patch the module console temporarily
    import env_guard.output as mod
    original = mod.console
    mod.console = console
    try:
        func(*args, **kwargs)
    finally:
        mod.console = original
    return buf.getvalue()


class TestRenderScanResult:
    def test_perfect_score(self):
        r = ScanResult(["a.py"], [], [], [], 10)
        output = capture_output(render_scan_result, r)
        assert "A+" in output
        assert "100" in output

    def test_with_issues(self):
        issues = [
            EnvIssue(IssueType.MISSING_REQUIRED, Severity.CRITICAL, "DB", "Missing"),
        ]
        r = ScanResult(["a.py"], [], issues, [], 5)
        output = capture_output(render_scan_result, r)
        assert "DB" in output

    def test_with_secrets(self):
        secrets = [
            SecretFinding("src/config.py", 5, "API_KEY", "api_key", "sk-****", Severity.CRITICAL),
        ]
        r = ScanResult(["a.py"], [], [], secrets, 5)
        output = capture_output(render_scan_result, r)
        assert "config.py" in output

    def test_no_issues_message(self):
        r = ScanResult(["a.py"], [], [], [], 5)
        output = capture_output(render_scan_result, r)
        assert "No issues" in output or "A+" in output


class TestRenderIssues:
    def test_render_issues_list(self):
        issues = [
            EnvIssue(IssueType.EMPTY_VALUE, Severity.MEDIUM, "FOO", "Empty", suggestion="Set value"),
            EnvIssue(IssueType.NAMING_CONVENTION, Severity.LOW, "badName", "Bad naming"),
        ]
        output = capture_output(render_issues, issues)
        assert "FOO" in output
        assert "badName" in output

    def test_render_critical_issue(self):
        issues = [
            EnvIssue(IssueType.MISSING_REQUIRED, Severity.CRITICAL, "DB_URL", "Missing", suggestion="Add DB_URL"),
        ]
        output = capture_output(render_issues, issues)
        assert "DB_URL" in output


class TestRenderSecrets:
    def test_render_secrets_list(self):
        secrets = [
            SecretFinding("app.py", 10, "PASSWORD", "password", "****", Severity.HIGH),
        ]
        output = capture_output(render_secrets, secrets)
        assert "app.py" in output
        assert "PASSWORD" in output or "password" in output


class TestRenderEnvFileInfo:
    def test_render_file_info(self):
        ef = EnvFile(
            path=".env",
            variables={
                "APP_NAME": EnvVar("APP_NAME", "test", 1, ".env"),
                "PORT": EnvVar("PORT", "8080", 2, ".env"),
            },
        )
        output = capture_output(render_env_file_info, ef)
        assert "APP_NAME" in output
        assert "2" in output  # count

    def test_secret_masked(self):
        ef = EnvFile(
            path=".env",
            variables={
                "API_KEY": EnvVar("API_KEY", "supersecret", 1, ".env"),
            },
        )
        output = capture_output(render_env_file_info, ef)
        assert "supersecret" not in output
        assert "****" in output


class TestRenderDiff:
    def test_identical_files(self):
        d = EnvDiff(".env", ".env.prod", [], [], [], ["A", "B"])
        output = capture_output(render_diff, d)
        assert "identical" in output.lower()

    def test_with_differences(self):
        d = EnvDiff(
            ".env", ".env.prod",
            missing_in_target=["X"],
            missing_in_source=["Y"],
            different_values=[("Z", "1", "2")],
            same=["A"],
        )
        output = capture_output(render_diff, d)
        assert "X" in output
        assert "Y" in output
        assert "Z" in output

    def test_missing_only(self):
        d = EnvDiff(".env", ".env.prod", missing_in_target=["FOO"], missing_in_source=[], different_values=[], same=[])
        output = capture_output(render_diff, d)
        assert "FOO" in output


class TestRenderSyncResult:
    def test_no_changes(self):
        output = capture_output(render_sync_result, [])
        assert "sync" in output.lower() or "no changes" in output.lower()

    def test_with_changes(self):
        changes = ["Added B=default", "Added C=default"]
        output = capture_output(render_sync_result, changes)
        assert "B" in output

    def test_dry_run(self):
        changes = ["Added B=default"]
        output = capture_output(render_sync_result, changes, dry_run=True)
        assert "DRY RUN" in output
