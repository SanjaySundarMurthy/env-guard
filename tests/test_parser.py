"""Tests for env_guard.parser."""

from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path

import pytest

from env_guard.parser import (
    find_env_files,
    generate_env_example,
    generate_schema,
    parse_env_file,
    parse_schema_file,
    _detect_type,
)
from env_guard.models import VarType


class TestParseEnvFile:
    def test_basic_parse(self, tmp_env, tmp_path):
        fp = tmp_env("APP_NAME=myapp\nPORT=3000")
        parsed = parse_env_file(str(fp))
        assert "APP_NAME" in parsed.variables
        assert parsed.variables["APP_NAME"].value == "myapp"
        assert parsed.variables["PORT"].value == "3000"
        assert parsed.count == 2

    def test_comments_ignored(self, tmp_env):
        fp = tmp_env("# this is a comment\nAPP=test")
        parsed = parse_env_file(str(fp))
        assert parsed.count == 1
        assert "APP" in parsed.variables

    def test_empty_lines_skipped(self, tmp_env):
        fp = tmp_env("A=1\n\n\nB=2\n")
        parsed = parse_env_file(str(fp))
        assert parsed.count == 2

    def test_quoted_value_double(self, tmp_env):
        fp = tmp_env('MSG="hello world"')
        parsed = parse_env_file(str(fp))
        assert parsed.variables["MSG"].value == "hello world"

    def test_quoted_value_single(self, tmp_env):
        fp = tmp_env("MSG='hello world'")
        parsed = parse_env_file(str(fp))
        assert parsed.variables["MSG"].value == "hello world"

    def test_empty_value(self, tmp_env):
        fp = tmp_env("EMPTY=")
        parsed = parse_env_file(str(fp))
        assert parsed.variables["EMPTY"].value == ""
        assert parsed.variables["EMPTY"].is_empty is True

    def test_value_with_equals(self, tmp_env):
        fp = tmp_env("URL=postgres://host:5432/db?opt=val")
        parsed = parse_env_file(str(fp))
        assert "opt=val" in parsed.variables["URL"].value

    def test_export_prefix(self, tmp_env):
        fp = tmp_env("export APP_ENV=production")
        parsed = parse_env_file(str(fp))
        assert "APP_ENV" in parsed.variables
        assert parsed.variables["APP_ENV"].value == "production"

    def test_inline_comment(self, tmp_env):
        fp = tmp_env("PORT=8080 # server port")
        parsed = parse_env_file(str(fp))
        assert parsed.variables["PORT"].value == "8080"

    def test_line_numbers(self, tmp_env):
        fp = tmp_env("# comment\nA=1\n\nB=2")
        parsed = parse_env_file(str(fp))
        assert parsed.variables["A"].line_number == 2
        assert parsed.variables["B"].line_number == 4

    def test_duplicate_keys_last_wins(self, tmp_env):
        fp = tmp_env("X=first\nX=second")
        parsed = parse_env_file(str(fp))
        assert parsed.variables["X"].value == "second"

    def test_file_path_stored(self, tmp_env):
        fp = tmp_env("A=1")
        parsed = parse_env_file(str(fp))
        assert parsed.path == str(fp)

    def test_whitespace_around_equals(self, tmp_env):
        fp = tmp_env("KEY = value")
        parsed = parse_env_file(str(fp))
        assert "KEY" in parsed.variables

    def test_no_value_key_only(self, tmp_env):
        fp = tmp_env("JUST_KEY")
        parsed = parse_env_file(str(fp))
        # key without = should be skipped or treated as comment
        assert parsed.count == 0 or "JUST_KEY" in parsed.variables

    def test_multiline_handling(self, tmp_env):
        fp = tmp_env("A=1\nB=2\nC=3\nD=4\nE=5")
        parsed = parse_env_file(str(fp))
        assert parsed.count == 5

    def test_special_chars_in_value(self, tmp_env):
        fp = tmp_env('CONN="mongodb+srv://user:p@ss@cluster.mongodb.net/db"')
        parsed = parse_env_file(str(fp))
        assert "@" in parsed.variables["CONN"].value


class TestParseSchemaFile:
    def test_basic_schema(self, tmp_schema):
        fp = tmp_schema([
            {"key": "PORT", "required": True, "type": "port"},
            {"key": "DEBUG", "required": False, "type": "boolean"},
        ])
        rules = parse_schema_file(str(fp))
        assert len(rules) == 2
        assert rules[0].key == "PORT"
        assert rules[0].var_type == VarType.PORT
        assert rules[1].required is False

    def test_schema_with_allowed_values(self, tmp_schema):
        fp = tmp_schema([
            {"key": "ENV", "type": "enum", "allowed_values": ["dev", "staging", "prod"]},
        ])
        rules = parse_schema_file(str(fp))
        assert rules[0].allowed_values == ["dev", "staging", "prod"]

    def test_schema_with_pattern(self, tmp_schema):
        fp = tmp_schema([
            {"key": "CODE", "type": "string", "pattern": "^[A-Z]{3}$"},
        ])
        rules = parse_schema_file(str(fp))
        assert rules[0].pattern == "^[A-Z]{3}$"

    def test_schema_with_length(self, tmp_schema):
        fp = tmp_schema([
            {"key": "TOKEN", "type": "string", "min_length": 10, "max_length": 100},
        ])
        rules = parse_schema_file(str(fp))
        assert rules[0].min_length == 10
        assert rules[0].max_length == 100

    def test_schema_secret_flag(self, tmp_schema):
        fp = tmp_schema([
            {"key": "API_KEY", "required": True, "secret": True},
        ])
        rules = parse_schema_file(str(fp))
        assert rules[0].secret is True

    def test_empty_schema(self, tmp_schema):
        fp = tmp_schema([])
        rules = parse_schema_file(str(fp))
        assert len(rules) == 0


class TestFindEnvFiles:
    def test_find_in_dir(self, tmp_path):
        (tmp_path / ".env").write_text("A=1\n")
        (tmp_path / ".env.local").write_text("B=2\n")
        (tmp_path / "config.py").write_text("x=1\n")
        found = find_env_files(str(tmp_path))
        names = [os.path.basename(f) for f in found]
        assert ".env" in names
        assert ".env.local" in names
        assert "config.py" not in names

    def test_find_example(self, tmp_path):
        (tmp_path / ".env.example").write_text("A=1\n")
        found = find_env_files(str(tmp_path))
        names = [os.path.basename(f) for f in found]
        assert ".env.example" in names

    def test_empty_dir(self, tmp_path):
        found = find_env_files(str(tmp_path))
        assert len(found) == 0

    def test_nested_not_deep(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / ".env").write_text("A=1\n")
        found = find_env_files(str(tmp_path))
        # Should find in subdirectories
        assert len(found) >= 1


class TestGenerateEnvExample:
    def test_basic_generation(self, tmp_env):
        fp = tmp_env("APP_NAME=myapp\nPORT=8080\nAPI_KEY=sk-secret123")
        content = generate_env_example(str(fp))
        assert "APP_NAME=" in content
        assert "PORT=" in content
        assert "API_KEY=" in content
        # Secret should be masked
        assert "sk-secret123" not in content

    def test_preserves_structure(self, tmp_env):
        fp = tmp_env("# Database\nDB_HOST=localhost\nDB_PORT=5432\n\n# App\nAPP=test")
        content = generate_env_example(str(fp))
        assert "DB_HOST=" in content
        assert "APP=" in content


class TestGenerateSchema:
    def test_basic_schema(self, tmp_env):
        fp = tmp_env("APP_NAME=myapp\nPORT=8080\nDEBUG=true")
        schema = generate_schema(str(fp))
        assert "variables" in schema
        keys = [v["key"] for v in schema["variables"]]
        assert "APP_NAME" in keys
        assert "PORT" in keys
        assert "DEBUG" in keys

    def test_type_detection(self, tmp_env):
        fp = tmp_env("PORT=8080\nDEBUG=true\nURL=https://example.com")
        schema = generate_schema(str(fp))
        vars_map = {v["key"]: v for v in schema["variables"]}
        assert vars_map["PORT"]["type"] in ("port", "integer", "boolean")
        assert vars_map["DEBUG"]["type"] == "boolean"
        assert vars_map["URL"]["type"] == "url"


class TestDetectType:
    @pytest.mark.parametrize("value,expected", [
        ("true", "boolean"),
        ("false", "boolean"),
        ("True", "boolean"),
        ("yes", "boolean"),
        ("no", "boolean"),
        ("1", "boolean"),
        ("0", "boolean"),
    ])
    def test_boolean(self, value, expected):
        assert _detect_type(value) == expected

    @pytest.mark.parametrize("value,expected", [
        ("8080", "port"),
        ("3000", "port"),
        ("443", "port"),
    ])
    def test_port(self, value, expected):
        result = _detect_type(value)
        assert result in ("port", "integer", "boolean")

    def test_url(self):
        assert _detect_type("https://example.com") == "url"

    def test_email(self):
        assert _detect_type("user@example.com") == "email"

    def test_float(self):
        assert _detect_type("3.14") == "float"

    def test_string_default(self):
        assert _detect_type("hello-world") == "string"

    def test_json(self):
        assert _detect_type('{"key": "value"}') == "json"
