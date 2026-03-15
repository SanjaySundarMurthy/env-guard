"""Diff and sync operations for env files."""

from __future__ import annotations

import os
from typing import Optional

from env_guard.models import EnvDiff, EnvFile, EnvIssue, IssueType, Severity
from env_guard.parser import parse_env_file


def diff_env_files(source: EnvFile, target: EnvFile) -> EnvDiff:
    """Compare two env files and return differences."""
    source_keys = source.keys
    target_keys = target.keys

    missing_in_target = sorted(source_keys - target_keys)
    missing_in_source = sorted(target_keys - source_keys)
    common_keys = source_keys & target_keys

    different_values = []
    same = []

    for key in sorted(common_keys):
        src_val = source.variables[key].value
        tgt_val = target.variables[key].value
        if src_val != tgt_val:
            different_values.append((key, src_val, tgt_val))
        else:
            same.append(key)

    return EnvDiff(
        source_path=source.path,
        target_path=target.path,
        missing_in_target=missing_in_target,
        missing_in_source=missing_in_source,
        different_values=different_values,
        same=same,
    )


def compare_with_example(
    env_file_or_path,
    example_file_or_path,
) -> list[EnvIssue]:
    """Compare .env with .env.example and find discrepancies."""
    if isinstance(env_file_or_path, str):
        env_file = parse_env_file(env_file_or_path)
    else:
        env_file = env_file_or_path
    if isinstance(example_file_or_path, str):
        example_file = parse_env_file(example_file_or_path)
    else:
        example_file = example_file_or_path

    issues = []

    env_keys = env_file.keys
    example_keys = example_file.keys

    # Variables in example but missing from .env
    for key in sorted(example_keys - env_keys):
        issues.append(EnvIssue(
            type=IssueType.MISSING_IN_EXAMPLE,
            severity=Severity.HIGH,
            key=key,
            message=f"Variable '{key}' exists in {example_file.path} but missing from {env_file.path}",
            file_path=env_file.path,
            suggestion=f"Add {key}= to {env_file.path}",
        ))

    # Variables in .env but not in example
    for key in sorted(env_keys - example_keys):
        issues.append(EnvIssue(
            type=IssueType.EXTRA_IN_EXAMPLE,
            severity=Severity.LOW,
            key=key,
            message=f"Variable '{key}' exists in {env_file.path} but not in {example_file.path}",
            file_path=example_file.path,
            suggestion=f"Add {key}= to {example_file.path} for documentation",
        ))

    return issues


def sync_env_with_example(
    env_file_or_path,
    example_file_or_path,
    add_missing: bool = True,
    dry_run: bool = False,
) -> list[str]:
    """Sync .env with .env.example, adding missing keys."""
    if isinstance(env_file_or_path, str):
        env_file = parse_env_file(env_file_or_path)
    else:
        env_file = env_file_or_path
    if isinstance(example_file_or_path, str):
        example_file = parse_env_file(example_file_or_path)
    else:
        example_file = example_file_or_path

    changes = []
    example_keys = example_file.keys
    env_keys = env_file.keys

    missing = sorted(example_keys - env_keys)

    if not missing:
        return changes

    if not dry_run and add_missing:
        # Read existing .env content
        existing_content = ""
        if os.path.exists(env_file.path):
            with open(env_file.path, encoding="utf-8") as f:
                existing_content = f.read()

        # Append missing variables
        additions = []
        for key in missing:
            example_var = example_file.variables[key]
            if example_var.comment:
                additions.append(f"# {example_var.comment}")
            additions.append(f"{key}=")
            changes.append(f"Added {key}")

        if additions:
            new_content = existing_content.rstrip("\n") + "\n\n# Added from example\n" + "\n".join(additions) + "\n"
            with open(env_file.path, "w", encoding="utf-8") as f:
                f.write(new_content)
    else:
        for key in missing:
            changes.append(f"Would add {key}")

    return changes


def merge_env_files(
    base: EnvFile,
    overlay: EnvFile,
    output_path: Optional[str] = None,
) -> EnvFile:
    """Merge two env files, overlay values take precedence."""
    merged_vars = dict(base.variables)
    merged_vars.update(overlay.variables)

    merged = EnvFile(
        path=output_path or base.path,
        variables=merged_vars,
    )

    if output_path:
        lines = []
        for key in sorted(merged_vars.keys()):
            var = merged_vars[key]
            if var.comment:
                lines.append(f"# {var.comment}")
            lines.append(f"{key}={var.value}")
        content = "\n".join(lines) + "\n"

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

    return merged
