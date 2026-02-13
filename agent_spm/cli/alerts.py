"""Alerts command — evaluate sessions against policies and display violations."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from agent_spm.adapters.claude_code import scan_sessions
from agent_spm.domain.models import Policy, Severity
from agent_spm.engine.evaluator import evaluate
from agent_spm.policies.defaults import DEFAULT_POLICY
from agent_spm.policies.loader import load_policy, load_policy_dir

console = Console()

_SEVERITY_COLORS = {
    "low": "dim",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


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
    help="Path to a YAML policy file or directory. Defaults to built-in policy.",
)
@click.option(
    "--severity",
    "min_severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="low",
    help="Minimum severity to display (default: low = show all).",
)
@click.option(
    "--limit",
    type=int,
    default=None,
    help="Maximum number of sessions to scan.",
)
def alerts(
    path: Path | None,
    policy_path: Path | None,
    min_severity: str,
    limit: int | None,
) -> None:
    """Evaluate agent sessions against security policies and show violations."""
    # Load policies
    policies = _load_policies(policy_path)

    # Scan sessions
    sessions = scan_sessions(base_dir=path, limit=limit)
    if not sessions:
        console.print("[yellow]No sessions found.[/yellow]")
        return

    # Evaluate
    all_alerts = evaluate(sessions, policies)

    # Filter by severity
    min_sev = Severity(min_severity)
    min_idx = _SEVERITY_ORDER.index(min_sev)
    filtered = [a for a in all_alerts if _SEVERITY_ORDER.index(a.severity) <= min_idx]

    # Sort: critical first, then by session/time
    filtered.sort(key=lambda a: (_SEVERITY_ORDER.index(a.severity), a.event.timestamp))

    policy_names = ", ".join(p.name for p in policies)
    console.print(
        f"\n[bold]Alerts[/bold] — "
        f"{len(sessions)} session(s), "
        f"{len(all_alerts)} total alerts, "
        f"{len(filtered)} shown "
        f"[dim](policies: {policy_names})[/dim]\n"
    )

    if not filtered:
        console.print("[green]No alerts.[/green]")
        return

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column("Severity", width=10)
    table.add_column("Rule", width=26)
    table.add_column("Session", width=14, style="dim")
    table.add_column("Time", style="dim", width=8)
    table.add_column("Target", min_width=35)

    for alert in filtered:
        sev_str = alert.severity.value
        color = _SEVERITY_COLORS.get(sev_str, "white")
        sev_display = f"[{color}]{sev_str.upper()}[/{color}]"

        session_display = alert.event.session_id[:12] + "…"
        time_str = alert.event.timestamp.strftime("%H:%M:%S")

        target = (
            alert.event.target.command or alert.event.target.path or alert.event.target.tool_name
        )
        if target and len(target) > 60:
            target = target[:57] + "..."

        table.add_row(sev_display, alert.rule_name, session_display, time_str, target or "")

    console.print(table)
    console.print()


def _load_policies(policy_path: Path | None) -> list[Policy]:
    if policy_path is None:
        return [DEFAULT_POLICY]
    if policy_path.is_dir():
        loaded = load_policy_dir(policy_path)
        return loaded if loaded else [DEFAULT_POLICY]
    return [load_policy(policy_path)]
