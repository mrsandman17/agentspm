"""CLI entry point for agent-spm."""

import click

from agent_spm.cli.scan import scan


@click.group()
@click.version_option(package_name="agent-spm")
def cli() -> None:
    """Agent Security Posture Manager — SSPM applied to AI agents."""


cli.add_command(scan)
