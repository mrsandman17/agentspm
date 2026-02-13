"""CLI entry point for agent-spm."""

import click

from agent_spm.cli.alerts import alerts
from agent_spm.cli.events import events
from agent_spm.cli.inventory import inventory
from agent_spm.cli.posture import posture
from agent_spm.cli.scan import scan


@click.group()
@click.version_option(package_name="agent-spm")
def cli() -> None:
    """Agent Security Posture Manager — SSPM applied to AI agents."""


cli.add_command(scan)
cli.add_command(inventory)
cli.add_command(events)
cli.add_command(alerts)
cli.add_command(posture)
