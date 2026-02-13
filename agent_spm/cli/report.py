"""Report command — generate a Markdown security posture report."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.markdown import Markdown

from agent_spm.adapters.claude_code import scan_sessions
from agent_spm.domain.models import Policy
from agent_spm.engine.evaluator import evaluate
from agent_spm.engine.report import generate_report, render_markdown
from agent_spm.policies.defaults import DEFAULT_POLICY
from agent_spm.policies.loader import load_policy, load_policy_dir

console = Console()


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
    type=int,
    default=None,
    help="Maximum number of sessions to scan.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write report to a Markdown file instead of printing to console.",
)
@click.option(
    "--top",
    type=int,
    default=10,
    show_default=True,
    help="Maximum number of top violations and elevated events to include.",
)
def report(
    path: Path | None,
    policy_path: Path | None,
    limit: int | None,
    output_path: Path | None,
    top: int,
) -> None:
    """Generate a Markdown security posture report for recent agent sessions."""
    policies = _load_policies(policy_path)
    sessions = scan_sessions(base_dir=path, limit=limit)

    if not sessions:
        console.print("[yellow]No sessions found.[/yellow]")
        return

    alerts = evaluate(sessions, policies)
    rep = generate_report(sessions, alerts, policies, top_n=top)
    md_text = render_markdown(rep)

    if output_path is not None:
        output_path.write_text(md_text, encoding="utf-8")
        console.print(f"[green]Report written to {output_path}[/green]")
    else:
        console.print(Markdown(md_text))


def _load_policies(policy_path: Path | None) -> list[Policy]:
    if policy_path is None:
        return [DEFAULT_POLICY]
    if policy_path.is_dir():
        loaded = load_policy_dir(policy_path)
        return loaded if loaded else [DEFAULT_POLICY]
    return [load_policy(policy_path)]
