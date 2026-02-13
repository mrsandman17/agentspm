"""Scan command — parse Claude Code session logs into events."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from agent_spm.engine.scanner import scan as run_scan

console = Console()


@click.command()
@click.option(
    "--path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Override the default ~/.claude/projects/ directory.",
)
@click.option(
    "--limit",
    type=int,
    default=None,
    help="Maximum number of sessions to scan.",
)
@click.option(
    "--elevated",
    is_flag=True,
    default=False,
    help="Only show elevated permission events.",
)
def scan(path: Path | None, limit: int | None, elevated: bool) -> None:
    """Parse recent Claude Code sessions and display events."""
    sessions = run_scan(base_dir=path, limit=limit)

    if not sessions:
        console.print("[yellow]No sessions found.[/yellow]")
        return

    total_events = sum(s.total_events for s in sessions)
    total_elevated = sum(len(s.elevated_events) for s in sessions)

    console.print(
        f"\n[bold]Scanned {len(sessions)} session(s)[/bold] — "
        f"{total_events} events, {total_elevated} elevated\n"
    )

    for session in sessions:
        events = session.elevated_events if elevated else session.events
        if not events:
            continue

        # Session header
        model_str = session.model or "unknown"
        time_str = session.started_at.strftime("%Y-%m-%d %H:%M") if session.started_at else "?"
        console.print(
            f"[bold cyan]Session[/bold cyan] {session.session_id[:12]}… "
            f"[dim]model={model_str} started={time_str} "
            f"cwd={session.cwd or '?'}[/dim]"
        )

        # Events table
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
        table.add_column("Time", style="dim", width=8)
        table.add_column("Action", width=12)
        table.add_column("Target", min_width=30)
        table.add_column("Elevated", width=9, justify="center")

        for event in events:
            time_str = event.timestamp.strftime("%H:%M:%S")

            # Color-code action types
            action_colors = {
                "file_read": "green",
                "file_write": "yellow",
                "shell_exec": "red",
                "tool_call": "blue",
            }
            action_str = event.action_type.value
            color = action_colors.get(action_str, "white")
            action_display = f"[{color}]{action_str}[/{color}]"

            # Build target display
            if event.target.command:
                target_display = event.target.command
                if len(target_display) > 60:
                    target_display = target_display[:57] + "..."
            elif event.target.path:
                target_display = event.target.path
            else:
                target_display = event.target.tool_name

            # Elevated badge
            elevated_display = "[bold red]ELEVATED[/bold red]" if event.elevated else ""

            table.add_row(time_str, action_display, target_display, elevated_display)

        console.print(table)
        console.print()
