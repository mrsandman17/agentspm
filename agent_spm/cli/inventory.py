"""Inventory command — show tools used across agent sessions."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from agent_spm.adapters.claude_code import scan_sessions
from agent_spm.engine.inventory import build_inventory

console = Console()

_ACTION_COLORS = {
    "file_read": "green",
    "file_write": "yellow",
    "shell_exec": "red",
    "tool_call": "blue",
}


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
def inventory(path: Path | None, limit: int | None) -> None:
    """Show tools used across agent sessions (SSPM application inventory)."""
    sessions = scan_sessions(base_dir=path, limit=limit)

    if not sessions:
        console.print("[yellow]No sessions found.[/yellow]")
        return

    entries = build_inventory(sessions)

    if not entries:
        console.print("[yellow]No tool calls found.[/yellow]")
        return

    total_calls = sum(e.call_count for e in entries)
    total_elevated = sum(e.elevated_count for e in entries)

    console.print(
        f"\n[bold]Tool Inventory[/bold] — "
        f"{len(sessions)} session(s), "
        f"{total_calls} total calls, "
        f"{total_elevated} elevated\n"
    )

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column("Tool", min_width=16)
    table.add_column("Category", width=12)
    table.add_column("Calls", width=7, justify="right")
    table.add_column("Sessions", width=9, justify="right")
    table.add_column("Elevated", width=9, justify="right")

    for entry in entries:
        action_str = entry.action_type.value
        color = _ACTION_COLORS.get(action_str, "white")
        category_display = f"[{color}]{action_str}[/{color}]"

        elevated_display = (
            f"[bold red]{entry.elevated_count}[/bold red]"
            if entry.elevated_count > 0
            else str(entry.elevated_count)
        )

        table.add_row(
            entry.tool_name,
            category_display,
            str(entry.call_count),
            str(entry.session_count),
            elevated_display,
        )

    console.print(table)
    console.print()
