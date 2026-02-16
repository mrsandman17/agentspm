"""Alerts command — evaluate sessions against policies, plus rule management."""

from __future__ import annotations

import re
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agent_spm.adapters.claude_code import scan_sessions
from agent_spm.domain.models import ActionType, Policy, PolicyRule, RuleMatch, Severity
from agent_spm.engine.evaluator import evaluate
from agent_spm.policies.loader import load_all_policies
from agent_spm.policies.writer import (
    CUSTOM_POLICY_PATH,
    clear_custom_rules,
    list_custom_rules,
    remove_custom_rule,
    save_custom_rule,
    set_rule_enabled,
)
from agent_spm.security.redaction import safe_target_text

console = Console()

_SEVERITY_COLORS = {
    "low": "dim",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


@click.group(invoke_without_command=True)
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
    type=click.IntRange(min=1),
    default=None,
    help="Maximum number of sessions to scan.",
)
@click.option(
    "--detail",
    is_flag=True,
    default=False,
    help="Show individual violations instead of the aggregated summary.",
)
@click.pass_context
def alerts(
    ctx: click.Context,
    path: Path | None,
    policy_path: Path | None,
    min_severity: str,
    limit: int | None,
    detail: bool,
) -> None:
    """Evaluate agent sessions against security policies and show violations.

    Sub-commands: rules, add, remove, clear, default, enable, disable
    """
    if ctx.invoked_subcommand is not None:
        return

    if detail:
        _list_alerts(path=path, policy_path=policy_path, min_severity=min_severity, limit=limit)
    else:
        _list_alerts_aggregated(
            path=path, policy_path=policy_path, min_severity=min_severity, limit=limit
        )


def _list_alerts_aggregated(
    path: Path | None,
    policy_path: Path | None,
    min_severity: str,
    limit: int | None,
) -> None:
    """Default alerts view: aggregated by rule (count + example target)."""
    policies = _load_policies(policy_path)
    sessions = scan_sessions(base_dir=path, limit=limit)
    if not sessions:
        console.print("[yellow]No sessions found.[/yellow]")
        return

    all_alerts = evaluate(sessions, policies)

    min_sev = Severity(min_severity)
    min_idx = _SEVERITY_ORDER.index(min_sev)
    filtered = [a for a in all_alerts if _SEVERITY_ORDER.index(a.severity) <= min_idx]

    policy_names = ", ".join(p.name for p in policies)
    console.print(
        f"\n[bold]Alerts[/bold] — "
        f"{len(sessions)} session(s), "
        f"{len(all_alerts)} violation(s) "
        f"[dim](policies: {policy_names})[/dim]\n"
    )

    if not filtered:
        console.print("[green]No alerts.[/green]")
        return

    # Aggregate by rule name
    from collections import defaultdict

    rule_counts: dict[str, int] = defaultdict(int)
    rule_severity: dict[str, Severity] = {}

    for alert in filtered:
        name = alert.rule_name
        rule_counts[name] += 1
        rule_severity[name] = alert.severity

    # Sort by severity (worst first), then count descending
    sorted_rules = sorted(
        rule_counts.keys(),
        key=lambda n: (_SEVERITY_ORDER.index(rule_severity[n]), -rule_counts[n]),
    )

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column("Severity", width=10)
    table.add_column("Rule", width=28)
    table.add_column("Count", width=7, justify="right")

    for name in sorted_rules:
        sev_str = rule_severity[name].value
        color = _SEVERITY_COLORS.get(sev_str, "white")
        sev_display = f"[{color}]{sev_str.upper()}[/{color}]"
        table.add_row(sev_display, name, str(rule_counts[name]))

    console.print(table)
    console.print("[dim]Use --detail to see individual violations.[/dim]\n")


def _list_alerts(
    path: Path | None,
    policy_path: Path | None,
    min_severity: str,
    limit: int | None,
) -> None:
    policies = _load_policies(policy_path)
    sessions = scan_sessions(base_dir=path, limit=limit)
    if not sessions:
        console.print("[yellow]No sessions found.[/yellow]")
        return

    all_alerts = evaluate(sessions, policies)

    min_sev = Severity(min_severity)
    min_idx = _SEVERITY_ORDER.index(min_sev)
    filtered = [a for a in all_alerts if _SEVERITY_ORDER.index(a.severity) <= min_idx]
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

        target = safe_target_text(alert.event.target)
        if target and len(target) > 60:
            target = target[:57] + "..."

        table.add_row(sev_display, alert.rule_name, session_display, time_str, target or "")

    console.print(table)
    console.print()


# ── Sub-commands ──────────────────────────────────────────────────────────────


@alerts.command("rules")
@click.option(
    "--policy",
    "policy_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Extra YAML policy file or directory to include.",
)
def rules_cmd(policy_path: Path | None) -> None:
    """List all configured policy rules with source and status."""
    policies = _load_policies(policy_path)
    total = sum(len(p.rules) for p in policies)
    enabled_count = sum(1 for p in policies for r in p.rules if r.enabled)
    disabled_count = total - enabled_count

    title = (
        f"Policy Rules \u2500\u2500 "
        f"{len(policies)} polic{'y' if len(policies) == 1 else 'ies'}, "
        f"{total} rules "
        f"({enabled_count} enabled, {disabled_count} disabled)"
    )

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column("Name", min_width=28)
    table.add_column("Severity", width=10)
    table.add_column("Source", width=10)
    table.add_column("Status", width=10)

    from agent_spm.policies.defaults import DEFAULT_POLICY

    default_rule_names = {r.name for r in DEFAULT_POLICY.rules}
    custom_rule_names = {r.get("name") for r in list_custom_rules()}

    for policy in policies:
        for rule in policy.rules:
            sev_str = rule.severity.value
            color = _SEVERITY_COLORS.get(sev_str, "white")
            sev_display = f"[{color}]{sev_str.upper()}[/{color}]"

            is_override = rule.name in custom_rule_names and rule.name in default_rule_names
            if is_override:
                source = "default"
                status = "enabled (override)" if rule.enabled else "disabled (override)"
                status_display = (
                    f"[green]{status}[/green]" if rule.enabled else f"[dim]{status}[/dim]"
                )
            elif rule.name in custom_rule_names:
                source = "custom"
                status_display = "[green]enabled[/green]" if rule.enabled else "[dim]disabled[/dim]"
            else:
                source = policy.name
                status_display = "[green]enabled[/green]" if rule.enabled else "[dim]disabled[/dim]"

            table.add_row(rule.name, sev_display, source, status_display)

    console.print(Panel(table, title=f"[bold]{title}[/bold]", expand=False))


@alerts.command("add")
def add_cmd() -> None:
    """Interactive wizard to create a new custom alert rule."""
    console.print(
        Panel(
            "[dim]Name:[/dim]            no-prod-deploys\n"
            "[dim]Description:[/dim]     Flag deployment commands to production\n"
            "[dim]Severity:[/dim]        critical\n"
            "[dim]Action types:[/dim]    shell_exec\n"
            "[dim]Command pattern:[/dim] deploy.*prod\n"
            "[dim]Path pattern:[/dim]    (empty)\n\n"
            "This rule fires when a shell command matches the regex [bold]deploy.*prod[/bold].",
            title="[bold]Example Rule[/bold]",
            expand=False,
        )
    )
    console.print()

    name = click.prompt('Rule name (lowercase with hyphens, e.g. "no-prod-deploys")')
    if not re.match(r"^[a-z0-9][a-z0-9-]*$", name):
        console.print("[red]Name must be lowercase alphanumeric with hyphens.[/red]")
        raise SystemExit(1)

    description = click.prompt("Description (what does this rule catch?)")

    sev_str = click.prompt(
        "Severity [low / medium / high / critical]",
        type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
        default="medium",
    )
    severity = Severity(sev_str.lower())

    console.print(
        "Action types — which agent actions should this rule check?\n"
        "  [cyan]shell_exec[/cyan]  = shell/terminal commands (Bash tool)\n"
        "  [cyan]file_read[/cyan]   = file reads (Read, NotebookRead tools)\n"
        "  [cyan]file_write[/cyan]  = file writes (Write, Edit tools)\n"
        "  [cyan]tool_call[/cyan]   = any other tool call (Glob, Grep, etc.)\n"
        "  [cyan]all[/cyan]         = match any action type"
    )
    action_input = click.prompt(
        'Comma-separated, or "all"',
        default="all",
    )
    action_types: list[ActionType] | None = None
    if action_input.strip().lower() != "all":
        action_types = []
        for part in action_input.split(","):
            part = part.strip()
            try:
                action_types.append(ActionType(part))
            except ValueError:
                console.print(f"[red]Unknown action type: {part}[/red]")
                raise SystemExit(1) from None

    console.print(
        "Command regex pattern — matches against shell commands.\n"
        '  Examples: [dim]"deploy.*prod"[/dim], [dim]"npm install -g"[/dim], '
        '[dim]"docker push"[/dim]'
    )
    command_pattern = click.prompt("  Command pattern (empty to skip)", default="") or None
    if command_pattern:
        try:
            re.compile(command_pattern)
        except re.error as e:
            console.print(f"[red]Invalid regex: {e}[/red]")
            raise SystemExit(1) from None

    console.print(
        "Path regex pattern — matches against file paths.\n"
        r'  Examples: [dim]"\.env$"[/dim], [dim]"/etc/"[/dim], [dim]"secrets/"[/dim]'
    )
    path_pattern = click.prompt("  Path pattern (empty to skip)", default="") or None
    if path_pattern:
        try:
            re.compile(path_pattern)
        except re.error as e:
            console.print(f"[red]Invalid regex: {e}[/red]")
            raise SystemExit(1) from None

    rule = PolicyRule(
        name=name,
        description=description,
        severity=severity,
        match=RuleMatch(
            action_types=action_types,
            command_pattern=command_pattern,
            path_pattern=path_pattern,
        ),
        enabled=True,
    )

    # Preview
    preview_lines = [f"Name: {rule.name}", f"Severity: {rule.severity.value.upper()}"]
    if action_types:
        preview_lines.append(f"Actions: {', '.join(at.value for at in action_types)}")
    if command_pattern:
        preview_lines.append(f"Command pattern: {command_pattern}")
    if path_pattern:
        preview_lines.append(f"Path pattern: {path_pattern}")
    console.print(
        Panel("\n".join(preview_lines), title="[bold]New Rule Preview[/bold]", expand=False)
    )

    if not click.confirm("Save this rule?", default=True):
        console.print("[yellow]Cancelled.[/yellow]")
        return

    saved_path = save_custom_rule(rule)
    console.print(f"[green]✓ Rule '{name}' saved to {saved_path}[/green]")


@alerts.command("remove")
@click.argument("name")
def remove_cmd(name: str) -> None:
    """Remove a custom rule by NAME."""
    if remove_custom_rule(name):
        console.print(f"[green]✓ Rule '{name}' removed.[/green]")
    else:
        console.print(f"[red]Rule '{name}' not found in custom rules.[/red]")
        raise SystemExit(1)


@alerts.command("clear")
def clear_cmd() -> None:
    """Remove all custom rules."""
    if not CUSTOM_POLICY_PATH.exists():
        console.print("[yellow]No custom rules to clear.[/yellow]")
        return
    if click.confirm("Remove all custom rules?", default=False):
        clear_custom_rules()
        console.print("[green]✓ All custom rules cleared.[/green]")
    else:
        console.print("[yellow]Cancelled.[/yellow]")


@alerts.command("default")
def default_cmd() -> None:
    """Reset to built-in defaults — delete custom.yml."""
    if not CUSTOM_POLICY_PATH.exists():
        console.print("[yellow]No custom rules file found. Already at defaults.[/yellow]")
        return
    if click.confirm(f"Delete {CUSTOM_POLICY_PATH} and revert to defaults?", default=False):
        CUSTOM_POLICY_PATH.unlink()
        console.print("[green]✓ Reverted to built-in defaults.[/green]")
    else:
        console.print("[yellow]Cancelled.[/yellow]")


@alerts.command("enable")
@click.argument("name")
def enable_cmd(name: str) -> None:
    """Enable a disabled rule by NAME (custom or default)."""
    if set_rule_enabled(name, enabled=True):
        console.print(f"[green]✓ Rule '{name}' enabled.[/green]")
    else:
        console.print(f"[red]Rule '{name}' not found.[/red]")
        raise SystemExit(1)


@alerts.command("disable")
@click.argument("name")
def disable_cmd(name: str) -> None:
    """Disable a rule by NAME without deleting it (works for default rules too)."""
    if set_rule_enabled(name, enabled=False):
        console.print(f"[dim]Rule '{name}' disabled.[/dim]")
    else:
        console.print(f"[red]Rule '{name}' not found.[/red]")
        raise SystemExit(1)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _load_policies(policy_path: Path | None) -> list[Policy]:
    return load_all_policies(user_policy_path=policy_path)
