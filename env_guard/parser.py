"""Parser for .env files and schema definitions."""

from __future__ import annotations

import json
import os
import re
from typing import Optional

from env_guard.models import (
    EnvFile,
    EnvVar,
    ValidationRule,
    VarType,
)


def parse_env_file(file_path: str) -> EnvFile:
    """Parse a .env file into an EnvFile object."""
    env_file = EnvFile(path=file_path)

    if not os.path.exists(file_path):
        return env_file

    try:
        with open(file_path, encoding="utf-8") as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        return env_file

    env_file.raw_lines = [line.rstrip("\n\r") for line in lines]

    for i, raw_line in enumerate(lines, 1):
        line = raw_line.strip()

        # Empty line
        if not line:
            continue

        # Full comment line
        if line.startswith("#"):
            env_file.comments.append(line)
            continue

        # Parse KEY=VALUE
        parsed = _parse_env_line(line, i, file_path)
        if parsed:
            # Handle duplicate keys (keep last)
            env_file.variables[parsed.key] = parsed

    return env_file


def _parse_env_line(line: str, line_number: int, file_path: str) -> Optional[EnvVar]:
    """Parse a single env line into an EnvVar."""
    # Handle export prefix
    if line.startswith("export "):
        line = line[7:].strip()

    # Split on first =
    if "=" not in line:
        return None

    key, _, value = line.partition("=")
    key = key.strip()

    if not key:
        return None

    # Handle inline comments
    comment = ""
    value = value.strip()

    # Handle quoted values
    if value and value[0] in ('"', "'"):
        quote_char = value[0]
        end_idx = value.find(quote_char, 1)
        if end_idx > 0:
            # Check for inline comment after closing quote
            remainder = value[end_idx + 1:].strip()
            if remainder.startswith("#"):
                comment = remainder[1:].strip()
            value = value[1:end_idx]
        else:
            # No closing quote, take as-is minus opening quote
            value = value[1:]
    else:
        # Unquoted — handle inline comment
        if " #" in value:
            value, _, comment = value.partition(" #")
            value = value.strip()
            comment = comment.strip()

    return EnvVar(
        key=key,
        value=value,
        line_number=line_number,
        file_path=file_path,
        comment=comment,
    )


def parse_env_example(file_path: str) -> EnvFile:
    """Parse a .env.example file (values are optional/placeholder)."""
    return parse_env_file(file_path)


def parse_schema_file(file_path: str) -> list[ValidationRule]:
    """Parse a .env.schema.json file into validation rules."""
    if not os.path.exists(file_path):
        return []

    try:
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

    rules = []

    # Get the variables definition
    if isinstance(data, dict) and "variables" in data:
        variables = data["variables"]
    elif isinstance(data, list):
        variables = data
    elif isinstance(data, dict):
        variables = data
    else:
        return rules

    # Handle list format: [{"key": "PORT", "type": "port", ...}, ...]
    if isinstance(variables, list):
        for spec in variables:
            if not isinstance(spec, dict) or "key" not in spec:
                continue
            rule = ValidationRule(
                key=spec["key"],
                required=spec.get("required", True),
                var_type=_parse_var_type(spec.get("type", "string")),
                pattern=spec.get("pattern"),
                min_length=spec.get("min_length"),
                max_length=spec.get("max_length"),
                allowed_values=spec.get("allowed_values") or spec.get("enum"),
                default=spec.get("default"),
                description=spec.get("description", ""),
                secret=spec.get("secret", False),
            )
            rules.append(rule)
    elif isinstance(variables, dict):
        # Dict format: {"KEY": {"type": "port"}, ...}
        for key, spec in variables.items():
            if isinstance(spec, str):
                rules.append(ValidationRule(key=key, var_type=_parse_var_type(spec)))
                continue
            if not isinstance(spec, dict):
                continue
            rule = ValidationRule(
                key=key,
                required=spec.get("required", True),
                var_type=_parse_var_type(spec.get("type", "string")),
                pattern=spec.get("pattern"),
                min_length=spec.get("min_length"),
                max_length=spec.get("max_length"),
                allowed_values=spec.get("allowed_values") or spec.get("enum"),
                default=spec.get("default"),
                description=spec.get("description", ""),
                secret=spec.get("secret", False),
            )
            rules.append(rule)

    return rules


def _parse_var_type(type_str: str) -> VarType:
    """Parse a type string into a VarType enum."""
    try:
        return VarType(type_str.lower())
    except ValueError:
        return VarType.STRING


def find_env_files(root: str, include_examples: bool = True) -> list[str]:
    """Find all .env files in a directory tree."""
    env_files = []
    patterns = [
        re.compile(r"^\.env$"),
        re.compile(r"^\.env\..+$"),  # .env.local, .env.production, etc.
    ]

    if include_examples:
        patterns.append(re.compile(r"^\.env\.example$"))
        patterns.append(re.compile(r"^\.env\.sample$"))
        patterns.append(re.compile(r"^\.env\.template$"))

    skip_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for filename in filenames:
            if any(p.match(filename) for p in patterns):
                full_path = os.path.join(dirpath, filename)
                env_files.append(os.path.abspath(full_path))

    return sorted(env_files)


def generate_env_example(env_file_or_path, mask_secrets: bool = True) -> str:
    """Generate a .env.example from an existing .env file."""
    from env_guard.models import is_secret_key

    if isinstance(env_file_or_path, str):
        env_file = parse_env_file(env_file_or_path)
    else:
        env_file = env_file_or_path

    lines = []
    lines.append("# Environment Variables")
    lines.append("# Copy this file to .env and fill in the values")
    lines.append("")

    for key, var in sorted(env_file.variables.items()):
        if var.comment:
            lines.append(f"# {var.comment}")

        if mask_secrets and is_secret_key(key):
            lines.append(f"{key}=")
        elif var.is_empty:
            lines.append(f"{key}=")
        else:
            lines.append(f"{key}={var.value}")

    return "\n".join(lines) + "\n"


def generate_schema(env_file_or_path) -> dict:
    """Generate a JSON schema from an existing .env file."""
    from env_guard.models import is_secret_key

    if isinstance(env_file_or_path, str):
        env_file = parse_env_file(env_file_or_path)
    else:
        env_file = env_file_or_path

    variables = []
    for key, var in sorted(env_file.variables.items()):
        spec: dict = {"key": key, "required": True}

        # Detect type from value
        spec["type"] = _detect_type(var.value)

        if is_secret_key(key):
            spec["secret"] = True

        if var.comment:
            spec["description"] = var.comment

        variables.append(spec)

    return {"variables": variables}


def _detect_type(value: str) -> str:
    """Heuristic type detection from a string value."""
    if not value:
        return "string"

    # Boolean
    if value.lower() in ("true", "false", "yes", "no", "1", "0", "on", "off"):
        return "boolean"

    # Integer
    try:
        int(value)
        port = int(value)
        if 1 <= port <= 65535:
            return "port"
        return "integer"
    except ValueError:
        pass

    # Float
    try:
        float(value)
        return "float"
    except ValueError:
        pass

    # URL
    if re.match(r"^https?://", value):
        return "url"

    # Email
    if re.match(r"^[^@]+@[^@]+\.[^@]+$", value):
        return "email"

    # Path
    if "/" in value or "\\" in value:
        if any(value.startswith(p) for p in ("/", "./", "../", "C:\\", "~/")):
            return "path"

    # JSON
    if value.startswith(("{", "[")):
        try:
            json.loads(value)
            return "json"
        except json.JSONDecodeError:
            pass

    return "string"
