"""CLI commands for env-guard."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click
from rich.console import Console

from env_guard import __version__
from env_guard.diff import compare_with_example, diff_env_files, sync_env_with_example
from env_guard.models import ScanResult
from env_guard.output import (
    render_diff,
    render_env_file_info,
    render_issues,
    render_scan_result,
    render_secrets,
    render_sync_result,
)
from env_guard.parser import (
    find_env_files,
    generate_env_example,
    generate_schema,
    parse_env_file,
    parse_schema_file,
)
from env_guard.scanner import (
    check_gitignore_for_env,
    scan_directory_for_secrets,
    scan_env_values,
)
from env_guard.validators import validate_env_file

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="env-guard")
def cli():
    """Environment variable validation, secret detection, and .env file management."""
    pass


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--schema", "-s", type=click.Path(exists=True), help="Schema file (.env.schema.json) for validation.")
@click.option("--env-file", "-e", type=click.Path(), help="Specific .env file to scan (auto-detected if not given).")
@click.option("--no-secrets", is_flag=True, help="Skip secret scanning in source files.")
@click.option("--strict", is_flag=True, help="Treat warnings as errors (exit code 1 on any issue).")
def scan(path: str, schema: str | None, env_file: str | None, no_secrets: bool, strict: bool):
    """Scan and validate environment configuration.

    Validates .env files, detects secrets, and checks for common issues.
    """
    target = Path(path).resolve()
    result = ScanResult(files_scanned=[], env_files=[], issues=[], secrets=[], total_variables=0)

    # Find env files
    if env_file:
        env_path = Path(env_file).resolve()
        if not env_path.exists():
            console.print(f"  [red]Error: File not found: {env_file}[/red]")
            sys.exit(1)
        env_paths = [env_path]
    else:
        search_dir = target if target.is_dir() else target.parent
        env_paths = find_env_files(str(search_dir))

    if not env_paths:
        console.print("  [yellow]No .env files found.[/yellow]")
        sys.exit(0)

    # Parse schema
    rules = None
    if schema:
        rules = parse_schema_file(schema)

    # Validate each env file
    for ep in env_paths:
        parsed = parse_env_file(str(ep))
        result.env_files.append(parsed)
        result.files_scanned.append(str(ep))
        result.total_variables += parsed.count

        # Validate
        issues = validate_env_file(parsed, rules)
        result.issues.extend(issues)

        # Scan env values for secret patterns
        secrets = scan_env_values(parsed)
        result.secrets.extend(secrets)

    # Scan source files for secrets
    if not no_secrets:
        scan_dir = str(target if target.is_dir() else target.parent)
        source_secrets = scan_directory_for_secrets(scan_dir)
        result.secrets.extend(source_secrets)
        # Count scanned files
        for root, _dirs, files in os.walk(scan_dir):
            for f in files:
                fp = os.path.join(root, f)
                if fp not in result.files_scanned:
                    result.files_scanned.append(fp)

    # Check gitignore
    gitignore_issues = check_gitignore_for_env(str(target if target.is_dir() else target.parent))
    result.issues.extend(gitignore_issues)

    render_scan_result(result)

    # Exit code
    if strict and result.total_issues > 0:
        sys.exit(1)
    elif result.has_critical:
        sys.exit(1)
    sys.exit(0)


@cli.command()
@click.argument("source", type=click.Path(exists=True))
@click.argument("target", type=click.Path(exists=True))
def diff(source: str, target: str):
    """Compare two .env files side by side.

    Shows missing, extra, and different variables between SOURCE and TARGET.
    """
    src = parse_env_file(source)
    tgt = parse_env_file(target)
    d = diff_env_files(src, tgt)
    render_diff(d)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--env-file", "-e", type=click.Path(), help="Source .env file.")
@click.option("--example-file", "-x", type=click.Path(), help=".env.example file.")
@click.option("--dry-run", is_flag=True, help="Show what would change without writing.")
def sync(path: str, env_file: str | None, example_file: str | None, dry_run: bool):
    """Sync .env with .env.example.

    Adds missing keys from .env.example to .env with placeholder values.
    """
    base = Path(path).resolve()
    if base.is_file():
        base = base.parent

    env_path = env_file or str(base / ".env")
    example_path = example_file or str(base / ".env.example")

    if not Path(env_path).exists():
        console.print(f"  [red]Error: {env_path} not found[/red]")
        sys.exit(1)
    if not Path(example_path).exists():
        console.print(f"  [red]Error: {example_path} not found[/red]")
        sys.exit(1)

    changes = sync_env_with_example(env_path, example_path, dry_run=dry_run)
    render_sync_result(changes, dry_run=dry_run)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--env-file", "-e", type=click.Path(exists=True), help="Specific .env file to validate.")
@click.option("--schema", "-s", type=click.Path(exists=True), required=True, help="Schema file for validation.")
@click.option("--strict", is_flag=True, help="Treat warnings as errors.")
def check(path: str, env_file: str | None, schema: str, strict: bool):
    """Validate .env against a schema file.

    Checks required variables, types, formats, and allowed values.
    """
    if env_file:
        env_path = env_file
    else:
        target = Path(path).resolve()
        candidate = target / ".env" if target.is_dir() else target
        if not candidate.exists():
            console.print("  [red]Error: No .env file found[/red]")
            sys.exit(1)
        env_path = str(candidate)

    parsed = parse_env_file(env_path)
    rules = parse_schema_file(schema)
    issues = validate_env_file(parsed, rules)

    if issues:
        console.print()
        render_issues(issues)
        if strict:
            sys.exit(1)
        critical = any(i.severity.value == "critical" for i in issues)
        if critical:
            sys.exit(1)
    else:
        console.print()
        console.print("  [green bold]Validation passed — no issues found![/green bold]")
        console.print()


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--include-env", is_flag=True, help="Also scan .env files (default: source files only).")
def secrets(path: str, include_env: bool):
    """Scan for hardcoded secrets in source files.

    Detects API keys, tokens, passwords, and other sensitive values.
    """
    target = Path(path).resolve()
    scan_dir = str(target if target.is_dir() else target.parent)

    findings = scan_directory_for_secrets(scan_dir)

    if include_env:
        env_files = find_env_files(scan_dir)
        for ef in env_files:
            parsed = parse_env_file(str(ef))
            env_secrets = scan_env_values(parsed)
            findings.extend(env_secrets)

    if findings:
        render_secrets(findings)
        sys.exit(1)
    else:
        console.print()
        console.print("  [green bold]No hardcoded secrets found![/green bold]")
        console.print()


@cli.command()
@click.argument("env_file", type=click.Path(exists=True))
def show(env_file: str):
    """Display contents of an .env file.

    Shows variables with secret values masked.
    """
    parsed = parse_env_file(env_file)
    render_env_file_info(parsed)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--env-file", "-e", type=click.Path(exists=True), help="Source .env file.")
@click.option("--output", "-o", type=click.Choice(["example", "schema"]), default="example", help="Output type.")
@click.option("--force", is_flag=True, help="Overwrite existing files.")
def init(path: str, env_file: str | None, output: str, force: bool):
    """Generate .env.example or .env.schema.json from an .env file.

    Creates template/schema files for sharing environment configuration.
    """
    base = Path(path).resolve()
    if base.is_file():
        base = base.parent

    source = env_file or str(base / ".env")
    if not Path(source).exists():
        console.print(f"  [red]Error: {source} not found[/red]")
        sys.exit(1)

    if output == "example":
        out_path = str(base / ".env.example")
        if Path(out_path).exists() and not force:
            console.print(f"  [yellow]{out_path} already exists. Use --force to overwrite.[/yellow]")
            sys.exit(1)
        content = generate_env_example(source)
        Path(out_path).write_text(content)
        console.print(f"  [green]Created:[/green] {out_path}")
    else:
        out_path = str(base / ".env.schema.json")
        if Path(out_path).exists() and not force:
            console.print(f"  [yellow]{out_path} already exists. Use --force to overwrite.[/yellow]")
            sys.exit(1)
        schema_data = generate_schema(source)
        Path(out_path).write_text(json.dumps(schema_data, indent=2) + "\n")
        console.print(f"  [green]Created:[/green] {out_path}")

    console.print()


def main():
    """Entry point."""
    cli()


if __name__ == "__main__":
    main()
