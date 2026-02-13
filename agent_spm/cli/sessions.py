"""Sessions command — directory-grouped view of Claude Code agent activity."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agent_spm.adapters.claude_code import scan_sessions
from agent_spm.domain.models import Policy, Session
from agent_spm.engine.evaluator import evaluate
from agent_spm.engine.inventory import build_inventory
from agent_spm.engine.posture import calculate_posture
from agent_spm.policies.loader import load_all_policies

console = Console()

_GRADE_COLORS = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}
_SEVERITY_COLORS = {"low": "dim", "medium": "yellow", "high": "red", "critical": "bold red"}
_ACTION_COLORS = {
    "file_read": "green",
    "file_write": "yellow",
    "shell_exec": "red",
    "tool_call": "blue",
}


@click.command()
@click.argument("session_id", required=False, default=None)
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
    type=int,
    default=None,
    help="Maximum number of sessions to scan.",
)
def sessions(
    session_id: str | None,
    path: Path | None,
    policy_path: Path | None,
    limit: int | None,
) -> None:
    """Show agent sessions grouped by working directory, or drill into a session."""
    all_sessions = scan_sessions(base_dir=path, limit=limit)

    if not all_sessions:
        console.print("[yellow]No sessions found.[/yellow]")
        return

    policies = load_all_policies(user_policy_path=policy_path)

    if session_id is not None:
        _render_session_detail(session_id, all_sessions, policies)
    else:
        _render_directory_overview(all_sessions, policies)


def _render_directory_overview(all_sessions: list[Session], policies: list[Policy]) -> None:
    groups = _group_by_directory(all_sessions)
    total_rules = sum(len(p.rules) for p in policies)

    title = (
        f"Agent Sessions \u2500\u2500 "
        f"{len(all_sessions)} session(s) across {len(groups)} "
        f"director{'y' if len(groups) == 1 else 'ies'} \u2500\u2500 "
        f"{total_rules} policy rule(s) loaded"
    )

    lines: list[str] = []
    for dir_path, dir_sessions in sorted(groups.items(), key=lambda kv: _last_activity(kv[1])):
        dir_alerts = evaluate(dir_sessions, policies)
        ps = calculate_posture(dir_sessions, dir_alerts)
        inventory = build_inventory(dir_sessions)

        last_dt = _last_activity(dir_sessions)
        last_str = _relative_time(last_dt) if last_dt else "?"

        session_count = len(dir_sessions)
        short_path = _shorten_path(dir_path)

        grade_color = _GRADE_COLORS.get(ps.grade, "white")
        elevated = sum(len(s.elevated_events) for s in dir_sessions)

        # Top tools (up to 5)
        top_tools = inventory[:5]
        tools_str = "  ".join(
            f"[dim]{entry.tool_name}[/dim]([cyan]{entry.call_count}[/cyan])" for entry in top_tools
        )

        lines.append(
            f"[bold]{short_path}[/bold]"
            f"  [dim]{session_count} session{'s' if session_count != 1 else ''}[/dim]"
            f"  │  last: [dim]{last_str}[/dim]"
        )
        lines.append(
            f"  Grade: [{grade_color}]{ps.grade}[/{grade_color}]"
            f"  │  Events: [cyan]{ps.total_events}[/cyan]"
            f"  │  Elevated: [yellow]{elevated}[/yellow]"
            f"  │  Alerts: [red]{ps.total_alerts}[/red]"
        )
        if top_tools:
            lines.append(f"  Tools: {tools_str}")
        lines.append("")

    body = "\n".join(lines).rstrip()
    console.print(Panel(body, title=f"[bold]{title}[/bold]", expand=False))
    console.print()


def _render_session_detail(
    prefix: str, all_sessions: list[Session], policies: list[Policy]
) -> None:
    matched = [s for s in all_sessions if s.session_id.startswith(prefix)]
    if not matched:
        console.print(f"[red]No session found with ID prefix '{prefix}'[/red]")
        return
    if len(matched) > 1:
        console.print(
            f"[yellow]Multiple sessions match prefix '{prefix}'. Using most recent.[/yellow]"
        )

    session = matched[0]
    alerts = evaluate([session], policies)
    inventory = build_inventory([session])

    # Metadata panel
    duration = _format_duration(session.started_at, session.ended_at)
    started_str = session.started_at.strftime("%Y-%m-%d %H:%M:%S") if session.started_at else "?"
    ended_str = session.ended_at.strftime("%Y-%m-%d %H:%M:%S") if session.ended_at else "ongoing"

    meta_lines = [
        f"[bold]Session[/bold]  {session.session_id}",
        f"[dim]CWD:[/dim]     {session.cwd or '?'}",
        f"[dim]Model:[/dim]   {session.model or '?'}",
        f"[dim]Start:[/dim]   {started_str}",
        f"[dim]End:[/dim]     {ended_str}",
        f"[dim]Duration:[/dim] {duration}",
    ]
    console.print(Panel("\n".join(meta_lines), title="[bold]Session Detail[/bold]", expand=False))
    console.print()

    # Tool usage
    if inventory:
        inv_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
        inv_table.add_column("Tool", width=20)
        inv_table.add_column("Calls", width=8, justify="right")
        inv_table.add_column("Elevated", width=10, justify="right")
        for entry in inventory:
            color = _ACTION_COLORS.get(entry.action_type.value, "white")
            inv_table.add_row(
                f"[{color}]{entry.tool_name}[/{color}]",
                str(entry.call_count),
                str(entry.elevated_count) if entry.elevated_count else "—",
            )
        console.print("[bold]Tool Usage[/bold]")
        console.print(inv_table)
        console.print()

    # Events table
    if session.events:
        ev_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
        ev_table.add_column("Time", style="dim", width=8)
        ev_table.add_column("Action", width=12)
        ev_table.add_column("Target", min_width=30)
        ev_table.add_column("Elevated", width=9, justify="center")

        for event in session.events:
            time_str = event.timestamp.strftime("%H:%M:%S")
            action_str = event.action_type.value
            color = _ACTION_COLORS.get(action_str, "white")
            action_display = f"[{color}]{action_str}[/{color}]"

            if event.target.command:
                target_display = event.target.command[:60] + (
                    "..." if len(event.target.command) > 60 else ""
                )
            elif event.target.path:
                target_display = event.target.path
            else:
                target_display = event.target.tool_name

            elevated_display = "[bold red]ELEVATED[/bold red]" if event.elevated else ""
            ev_table.add_row(time_str, action_display, target_display, elevated_display)

        console.print("[bold]Events[/bold]")
        console.print(ev_table)
        console.print()

    # Alerts table
    if alerts:
        from agent_spm.domain.models import Severity

        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        alerts_sorted = sorted(
            alerts, key=lambda a: (severity_order.index(a.severity), a.event.timestamp)
        )

        al_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
        al_table.add_column("Severity", width=10)
        al_table.add_column("Rule", width=26)
        al_table.add_column("Time", style="dim", width=8)
        al_table.add_column("Target", min_width=35)

        for alert in alerts_sorted:
            sev_str = alert.severity.value
            color = _SEVERITY_COLORS.get(sev_str, "white")
            sev_display = f"[{color}]{sev_str.upper()}[/{color}]"
            time_str = alert.event.timestamp.strftime("%H:%M:%S")
            target = (
                alert.event.target.command
                or alert.event.target.path
                or alert.event.target.tool_name
            )
            if target and len(target) > 60:
                target = target[:57] + "..."
            al_table.add_row(sev_display, alert.rule_name, time_str, target or "")

        console.print(f"[bold]Alerts[/bold] ({len(alerts)} violation(s))")
        console.print(al_table)
        console.print()
    else:
        console.print("[green]No alerts for this session.[/green]")


def _group_by_directory(sessions: list[Session]) -> dict[str, list[Session]]:
    groups: dict[str, list[Session]] = {}
    for session in sessions:
        key = session.cwd or "(unknown)"
        groups.setdefault(key, []).append(session)
    return groups


def _last_activity(sessions: list[Session]) -> datetime | None:
    times = [s.ended_at or s.started_at for s in sessions if s.ended_at or s.started_at]
    return max(times) if times else None


def _relative_time(dt: datetime) -> str:
    now = datetime.now(tz=UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    diff = now - dt
    seconds = int(diff.total_seconds())
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def _format_duration(start: datetime | None, end: datetime | None) -> str:
    if not start:
        return "?"
    finish = end or datetime.now(tz=UTC)
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    if finish.tzinfo is None:
        finish = finish.replace(tzinfo=UTC)
    seconds = int((finish - start).total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, mins = divmod(minutes, 60)
    return f"{hours}h {mins}m"


def _shorten_path(path: str) -> str:
    home = os.path.expanduser("~")
    if path.startswith(home):
        return "~" + path[len(home) :]
    return path
