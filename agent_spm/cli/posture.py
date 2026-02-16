"""Posture command — security posture dashboard for agent sessions."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agent_spm.adapters.claude_code import scan_sessions
from agent_spm.domain.models import Policy, Severity
from agent_spm.engine.evaluator import evaluate
from agent_spm.engine.posture import calculate_posture
from agent_spm.policies.loader import load_all_policies

console = Console()

_GRADE_COLORS = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}
_SEVERITY_COLORS = {"low": "dim", "medium": "yellow", "high": "red", "critical": "bold red"}


@click.command()
@click.option(
    "--path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Override the default ~/.claude/projects/ directory.",
)
@click.option(
    "--policy",
    "policy_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to a YAML policy file or directory.",
)
@click.option(
    "--limit",
    type=click.IntRange(min=1),
    default=None,
    help="Maximum number of sessions to scan.",
)
def posture(path: Path | None, policy_path: Path | None, limit: int | None) -> None:
    """Show the security posture score for recent agent sessions."""
    policies = _load_policies(policy_path)
    sessions = scan_sessions(base_dir=path, limit=limit)

    if not sessions:
        console.print("[yellow]No sessions found.[/yellow]")
        return

    all_alerts = evaluate(sessions, policies)
    ps = calculate_posture(sessions, all_alerts)

    # ── Score panel ────────────────────────────────────────────────────────────
    grade_color = _GRADE_COLORS.get(ps.grade, "white")
    score_line = f"[bold]{ps.score}/100[/bold]  Grade: [{grade_color}]{ps.grade}[/{grade_color}]"
    policy_names = ", ".join(p.name for p in policies)
    meta = (
        f"Sessions: {ps.total_sessions}  "
        f"Events: {ps.total_events}  "
        f"Alerts: {ps.total_alerts}  "
        f"Elevated: {ps.elevated_event_ratio:.0%}  "
        f"[dim]Policies: {policy_names}[/dim]"
    )
    console.print(
        Panel(f"{score_line}\n{meta}", title="[bold]Security Posture[/bold]", expand=False)
    )
    console.print()

    # ── Alert breakdown table ──────────────────────────────────────────────────
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column("Severity", width=10)
    table.add_column("Alerts", width=8, justify="right")
    table.add_column("Deduction", width=10, justify="right")
    table.add_column("Cap", width=6, justify="right")

    from agent_spm.engine.posture import _DEDUCTIONS

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = ps.alerts_by_severity.get(sev, 0)
        per_alert, cap = _DEDUCTIONS[sev]
        actual_deduction = min(count * per_alert, cap)
        color = _SEVERITY_COLORS.get(sev.value, "white")

        sev_display = f"[{color}]{sev.value.upper()}[/{color}]"
        deduction_display = f"-{actual_deduction}" if actual_deduction else "0"
        table.add_row(sev_display, str(count), deduction_display, str(cap))

    console.print(table)
    console.print()


def _load_policies(policy_path: Path | None) -> list[Policy]:
    return load_all_policies(user_policy_path=policy_path)
