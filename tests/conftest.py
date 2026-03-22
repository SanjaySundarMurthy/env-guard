"""Shared fixtures for env-guard tests."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest


@pytest.fixture
def tmp_env(tmp_path):
    """Create a .env file and return (dir_path, file_path)."""

    def _write(content: str, filename: str = ".env") -> Path:
        fp = tmp_path / filename
        fp.write_text(textwrap.dedent(content).strip() + "\n")
        return fp

    return _write


@pytest.fixture
def tmp_schema(tmp_path):
    """Create a .env.schema.json file and return path."""

    def _write(rules: list[dict], filename: str = ".env.schema.json") -> Path:
        fp = tmp_path / filename
        fp.write_text(json.dumps({"variables": rules}, indent=2))
        return fp

    return _write


@pytest.fixture
def sample_env(tmp_env):
    """A realistic .env file."""
    return tmp_env("""
        # App config
        APP_NAME=my-app
        APP_PORT=8080
        DEBUG=true
        DATABASE_URL=postgres://user:pass@localhost:5432/mydb
        API_KEY=sk-1234567890abcdef
        SECRET_KEY=mysecretkey
        REDIS_URL=redis://localhost:6379
        LOG_LEVEL=info
        EMPTY_VAR=
        # COMMENTED_VAR=value
    """)


@pytest.fixture
def sample_example(tmp_env):
    """A .env.example file."""
    return tmp_env("""
        APP_NAME=your-app-name
        APP_PORT=8080
        DEBUG=false
        DATABASE_URL=postgres://user:pass@host:5432/db
        API_KEY=your-api-key
        SECRET_KEY=your-secret
        REDIS_URL=redis://localhost:6379
        LOG_LEVEL=info
        NEW_VAR=new-value
    """, ".env.example")


@pytest.fixture
def sample_schema(tmp_schema):
    """A schema file with validation rules."""
    return tmp_schema([
        {"key": "APP_NAME", "required": True, "type": "string", "description": "Application name"},
        {"key": "APP_PORT", "required": True, "type": "port", "description": "Application port"},
        {"key": "DEBUG", "required": False, "type": "boolean", "description": "Debug mode"},
        {"key": "DATABASE_URL", "required": True, "type": "url", "description": "Database connection URL"},
        {"key": "API_KEY", "required": True, "type": "string", "secret": True, "min_length": 10},
        {"key": "LOG_LEVEL", "required": False, "type": "enum", "allowed_values": ["debug", "info", "warn", "error"]},
    ])
