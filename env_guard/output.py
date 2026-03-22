"""Rich terminal output for env-guard."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from env_guard.models import (
    EnvDiff,
    EnvFile,
    EnvIssue,
    ScanResult,
    SecretFinding,
    Severity,
)

console = Console()


def render_scan_result(result: ScanResult) -> None:
    """Display full scan results."""
    console.print()

    # Health score panel
    grade_colors = {"A+": "green", "A": "green", "B": "yellow", "C": "yellow", "D": "red", "F": "red"}
    color = grade_colors.get(result.grade, "white")

    panel = Panel(
        Text.from_markup(
            f"  Grade: [bold {color}]{result.grade}[/bold {color}]  |  "
            f"Score: [bold]{result.health_score}[/bold]/100\n"
            f"  Variables: [cyan]{result.total_variables}[/cyan]  |  "
            f"Issues: [{'red' if result.total_issues else 'green'}]{result.total_issues}[/{'red' if result.total_issues else 'green'}]  |  "
            f"Files: {len(result.files_scanned)}"
        ),
        title="[bold]Environment Health[/bold]",
        border_style=color,
        padding=(0, 2),
    )
    console.print(panel)
    console.print()

    # Issues
    if result.issues:
        render_issues(result.issues)

    # Secret findings
    if result.secrets:
        render_secrets(result.secrets)

    # Summary
    if not result.issues and not result.secrets:
        console.print("  [green bold]No issues found![/green bold]")
        console.print()


def render_issues(issues: list[EnvIssue]) -> None:
    """Display validation issues."""
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Variable", min_width=20)
    table.add_column("Issue", min_width=30)
    table.add_column("Suggestion", style="dim")

    sev_colors = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }

    for issue in issues:
        color = sev_colors.get(issue.severity, "white")
        icon = "!" if issue.severity in (Severity.CRITICAL, Severity.HIGH) else "~"
        icon_color = "red" if issue.severity in (Severity.CRITICAL, Severity.HIGH) else "yellow"
        table.add_row(
            f"[{icon_color}]{icon}[/{icon_color}]",
            f"[{color}]{issue.severity.value.upper()}[/{color}]",
            f"[cyan]{issue.key}[/cyan]",
            issue.message,
            issue.suggestion or "",
        )

    console.print("  [bold]Issues[/bold]")
    console.print(table)
    console.print()


def render_secrets(secrets: list[SecretFinding]) -> None:
    """Display secret findings."""
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("", width=3)
    table.add_column("File", min_width=25)
    table.add_column("Line", width=6, justify="right")
    table.add_column("Pattern", min_width=20)
    table.add_column("Preview", style="dim")

    for secret in secrets:
        table.add_row(
            "[red]![/red]",
            f"[cyan]{secret.file_path}[/cyan]",
            str(secret.line_number) if secret.line_number else "",
            f"[red]{secret.pattern_name}[/red]",
            secret.value_preview,
        )

    console.print("  [bold red]Secrets Detected[/bold red]")
    console.print(table)
    console.print()


def render_env_file_info(env_file: EnvFile) -> None:
    """Display env file summary."""
    console.print()
    console.print(f"  [bold]File:[/bold] [cyan]{env_file.path}[/cyan]")
    console.print(f"  [bold]Variables:[/bold] {env_file.count}")
    console.print(f"  [bold]Empty:[/bold] {env_file.empty_count}")
    console.print(f"  [bold]Secrets:[/bold] {env_file.secret_count}")
    console.print()

    if env_file.variables:
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Key", min_width=25, style="cyan")
        table.add_column("Value", min_width=30)
        table.add_column("Line", width=5, justify="right", style="dim")

        from env_guard.models import is_secret_key

        for key in sorted(env_file.variables.keys()):
            var = env_file.variables[key]
            if is_secret_key(key) and var.value:
                display_val = "[red]****[/red]"
            elif var.is_empty:
                display_val = "[dim](empty)[/dim]"
            else:
                display_val = var.value[:50] + ("..." if len(var.value) > 50 else "")
            table.add_row(key, display_val, str(var.line_number))

        console.print(table)
        console.print()


def render_diff(diff: EnvDiff) -> None:
    """Display diff between two env files."""
    console.print()
    console.print(f"  [bold]Comparing:[/bold] [cyan]{diff.source_path}[/cyan] vs [cyan]{diff.target_path}[/cyan]")
    console.print()

    if not diff.has_differences:
        console.print("  [green]Files are identical[/green]")
        console.print()
        return

    if diff.missing_in_target:
        console.print(f"  [bold red]Missing in {diff.target_path}:[/bold red]")
        for key in diff.missing_in_target:
            console.print(f"    [red]- {key}[/red]")
        console.print()

    if diff.missing_in_source:
        console.print(f"  [bold yellow]Extra in {diff.target_path}:[/bold yellow]")
        for key in diff.missing_in_source:
            console.print(f"    [green]+ {key}[/green]")
        console.print()

    if diff.different_values:
        console.print("  [bold]Different values:[/bold]")
        from env_guard.models import is_secret_key
        for key, src_val, tgt_val in diff.different_values:
            if is_secret_key(key):
                console.print(f"    [yellow]~ {key}[/yellow]: [dim]****[/dim] vs [dim]****[/dim]")
            else:
                console.print(f"    [yellow]~ {key}[/yellow]: [dim]{src_val[:30]}[/dim] vs [dim]{tgt_val[:30]}[/dim]")
        console.print()

    # Summary
    console.print(
        f"  [dim]Total: {diff.total_keys} keys | "
        f"{len(diff.missing_in_target)} missing | "
        f"{len(diff.missing_in_source)} extra | "
        f"{len(diff.different_values)} different | "
        f"{len(diff.same)} same[/dim]"
    )
    console.print()


def render_sync_result(changes: list[str], dry_run: bool = False) -> None:
    """Display sync results."""
    mode = "[yellow][DRY RUN][/yellow] " if dry_run else ""
    console.print()
    if not changes:
        console.print(f"  {mode}[green]Already in sync — no changes needed[/green]")
    else:
        console.print(f"  {mode}[bold]Changes:[/bold]")
        for change in changes:
            console.print(f"    [green]+[/green] {change}")
    console.print()
