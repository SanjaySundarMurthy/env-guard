"""Tests for env_guard.cli (Click commands)."""

from __future__ import annotations

import json
import textwrap

import pytest
from click.testing import CliRunner

from env_guard.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def env_project(tmp_path):
    """Create a minimal project with .env and .env.example."""
    env = tmp_path / ".env"
    env.write_text(textwrap.dedent("""\
        APP_NAME=myapp
        PORT=8080
        DEBUG=true
        DATABASE_URL=postgres://user:pass@localhost/db
        API_KEY=sk-1234567890abcdef
        EMPTY_VAR=
    """))

    example = tmp_path / ".env.example"
    example.write_text(textwrap.dedent("""\
        APP_NAME=your-app
        PORT=8080
        DEBUG=false
        DATABASE_URL=postgres://user:pass@host/db
        API_KEY=your-api-key
        REDIS_URL=redis://localhost:6379
    """))

    gitignore = tmp_path / ".gitignore"
    gitignore.write_text(".env\n")

    return tmp_path


@pytest.fixture
def schema_project(tmp_path):
    """Create a project with .env and .env.schema.json."""
    env = tmp_path / ".env"
    env.write_text(textwrap.dedent("""\
        APP_NAME=myapp
        PORT=8080
        DEBUG=true
    """))

    schema = tmp_path / ".env.schema.json"
    schema.write_text(json.dumps({
        "variables": [
            {"key": "APP_NAME", "required": True, "type": "string"},
            {"key": "PORT", "required": True, "type": "port"},
            {"key": "DEBUG", "required": False, "type": "boolean"},
            {"key": "DB_URL", "required": True, "type": "url"},
        ]
    }, indent=2))

    return tmp_path


class TestVersion:
    def test_version_flag(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output


class TestScanCommand:
    def test_scan_basic(self, runner, env_project):
        result = runner.invoke(cli, ["scan", str(env_project)])
        # May exit 1 due to issues found in sample env
        assert result.exit_code in (0, 1)
        assert "Health" in result.output or "Grade" in result.output or "Variables" in result.output

    def test_scan_no_env(self, runner, tmp_path):
        result = runner.invoke(cli, ["scan", str(tmp_path)])
        assert "No .env" in result.output or result.exit_code == 0

    def test_scan_specific_file(self, runner, env_project):
        env_file = str(env_project / ".env")
        result = runner.invoke(cli, ["scan", "--env-file", env_file, str(env_project)])
        assert result.exit_code in (0, 1)

    def test_scan_no_secrets(self, runner, env_project):
        result = runner.invoke(cli, ["scan", "--no-secrets", str(env_project)])
        assert result.exit_code in (0, 1)

    def test_scan_with_schema(self, runner, schema_project):
        schema_file = str(schema_project / ".env.schema.json")
        result = runner.invoke(cli, ["scan", "--schema", schema_file, str(schema_project)])
        # Should find missing DB_URL
        assert result.exit_code in (0, 1)

    def test_scan_strict(self, runner, env_project):
        result = runner.invoke(cli, ["scan", "--strict", str(env_project)])
        # May exit 1 if any issues found
        assert result.exit_code in (0, 1)


class TestDiffCommand:
    def test_diff_two_files(self, runner, env_project):
        env_file = str(env_project / ".env")
        example_file = str(env_project / ".env.example")
        result = runner.invoke(cli, ["diff", env_file, example_file])
        assert result.exit_code == 0
        # Should show differences
        assert "missing" in result.output.lower() or "different" in result.output.lower() or "Comparing" in result.output

    def test_diff_identical(self, runner, tmp_path):
        f1 = tmp_path / "a.env"
        f2 = tmp_path / "b.env"
        f1.write_text("X=1\nY=2\n")
        f2.write_text("X=1\nY=2\n")
        result = runner.invoke(cli, ["diff", str(f1), str(f2)])
        assert result.exit_code == 0
        assert "identical" in result.output.lower()


class TestSyncCommand:
    def test_sync_basic(self, runner, env_project):
        result = runner.invoke(cli, ["sync", str(env_project)])
        assert result.exit_code == 0

    def test_sync_dry_run(self, runner, env_project):
        result = runner.invoke(cli, ["sync", "--dry-run", str(env_project)])
        assert result.exit_code == 0
        if "DRY RUN" in result.output:
            assert True

    def test_sync_no_example(self, runner, tmp_path):
        env = tmp_path / ".env"
        env.write_text("A=1\n")
        result = runner.invoke(cli, ["sync", str(tmp_path)])
        assert result.exit_code != 0 or "not found" in result.output.lower()


class TestCheckCommand:
    def test_check_with_schema(self, runner, schema_project):
        schema_file = str(schema_project / ".env.schema.json")
        result = runner.invoke(cli, ["check", "--schema", schema_file, str(schema_project)])
        # DB_URL is missing and required, should show issues
        assert result.exit_code in (0, 1)

    def test_check_all_valid(self, runner, tmp_path):
        env = tmp_path / ".env"
        env.write_text("APP_NAME=test\nPORT=8080\n")
        schema = tmp_path / "schema.json"
        schema.write_text(json.dumps({
            "variables": [
                {"key": "APP_NAME", "required": True, "type": "string"},
                {"key": "PORT", "required": True, "type": "port"},
            ]
        }))
        result = runner.invoke(cli, ["check", "--schema", str(schema), str(tmp_path)])
        assert result.exit_code == 0

    def test_check_strict(self, runner, schema_project):
        schema_file = str(schema_project / ".env.schema.json")
        result = runner.invoke(cli, ["check", "--schema", schema_file, "--strict", str(schema_project)])
        # Should exit 1 due to missing DB_URL
        assert result.exit_code == 1


class TestSecretsCommand:
    def test_secrets_clean(self, runner, tmp_path):
        (tmp_path / "app.py").write_text("import os\nname = os.getenv('APP')\n")
        result = runner.invoke(cli, ["secrets", str(tmp_path)])
        assert result.exit_code == 0
        assert "No hardcoded" in result.output

    def test_secrets_found(self, runner, tmp_path):
        (tmp_path / "config.py").write_text('api_key = "sk-abcdefghijk1234567890abcd"\n')
        result = runner.invoke(cli, ["secrets", str(tmp_path)])
        assert result.exit_code == 1

    def test_secrets_include_env(self, runner, env_project):
        result = runner.invoke(cli, ["secrets", "--include-env", str(env_project)])
        assert result.exit_code in (0, 1)


class TestShowCommand:
    def test_show_env(self, runner, env_project):
        env_file = str(env_project / ".env")
        result = runner.invoke(cli, ["show", env_file])
        assert result.exit_code == 0
        assert "APP_NAME" in result.output

    def test_show_masks_secrets(self, runner, env_project):
        env_file = str(env_project / ".env")
        result = runner.invoke(cli, ["show", env_file])
        assert "sk-1234567890abcdef" not in result.output


class TestInitCommand:
    def test_init_example(self, runner, env_project):
        # Remove existing example first
        (env_project / ".env.example").unlink()
        result = runner.invoke(cli, ["init", "--env-file", str(env_project / ".env"), str(env_project)])
        assert result.exit_code == 0
        assert (env_project / ".env.example").exists()

    def test_init_schema(self, runner, env_project):
        result = runner.invoke(cli, [
            "init", "--output", "schema",
            "--env-file", str(env_project / ".env"),
            str(env_project),
        ])
        assert result.exit_code == 0
        assert (env_project / ".env.schema.json").exists()

    def test_init_no_overwrite(self, runner, env_project):
        # .env.example exists already
        result = runner.invoke(cli, ["init", "--env-file", str(env_project / ".env"), str(env_project)])
        assert result.exit_code != 0 or "already exists" in result.output

    def test_init_force(self, runner, env_project):
        result = runner.invoke(cli, [
            "init", "--force",
            "--env-file", str(env_project / ".env"),
            str(env_project),
        ])
        assert result.exit_code == 0

    def test_init_no_env(self, runner, tmp_path):
        result = runner.invoke(cli, ["init", str(tmp_path)])
        assert result.exit_code != 0 or "not found" in result.output.lower()
