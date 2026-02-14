"""Events command — query and display agent events with filters."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from agent_spm.adapters.claude_code import scan_sessions
from agent_spm.domain.models import ActionType

console = Console()

_ACTION_COLORS = {
    "file_read": "green",
    "file_write": "yellow",
    "shell_exec": "red",
    "tool_call": "blue",
}

_VALID_ACTIONS = [a.value for a in ActionType]


@click.command()
@click.option(
    "--path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Override the default ~/.claude/projects/ directory.",
)
@click.option(
    "--action",
    "action_filter",
    type=click.Choice(_VALID_ACTIONS),
    default=None,
    help="Filter by action type (file_read, file_write, shell_exec, tool_call).",
)
@click.option(
    "--limit",
    type=int,
    default=None,
    help="Maximum number of events to display.",
)
def events(
    path: Path | None,
    action_filter: str | None,
    limit: int | None,
) -> None:
    """Query agent events with optional filters."""
    sessions = scan_sessions(base_dir=path, limit=None)

    if not sessions:
        console.print("[yellow]No sessions found.[/yellow]")
        return

    # Collect and filter events
    action_type = ActionType(action_filter) if action_filter else None
    all_events = []
    for session in sessions:
        for event in session.events:
            if action_type and event.action_type != action_type:
                continue
            all_events.append(event)

    if limit:
        all_events = all_events[:limit]

    if not all_events:
        console.print("[yellow]No events match the given filters.[/yellow]")
        return

    console.print(f"\n[bold]Events[/bold] — {len(all_events)} total\n")

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column("Session", width=14, style="dim")
    table.add_column("Time", style="dim", width=8)
    table.add_column("Action", width=12)
    table.add_column("Target", min_width=30)

    for event in all_events:
        session_display = event.session_id[:12] + "…"
        time_str = event.timestamp.strftime("%H:%M:%S")

        action_str = event.action_type.value
        color = _ACTION_COLORS.get(action_str, "white")
        action_display = f"[{color}]{action_str}[/{color}]"

        if event.target.command:
            target_display = event.target.command
            if len(target_display) > 55:
                target_display = target_display[:52] + "..."
        elif event.target.path:
            target_display = event.target.path
        else:
            target_display = event.target.tool_name

        table.add_row(session_display, time_str, action_display, target_display)

    console.print(table)
    console.print()
