"""Scanner service — orchestrates log parsing into normalized events.

This is the entry point for the Scanning bounded context. It delegates
to framework-specific adapters (Claude Code for now) and returns
domain objects.
"""

from __future__ import annotations

from pathlib import Path

from agent_spm.adapters.claude_code import scan_sessions
from agent_spm.domain.models import Session


def scan(
    base_dir: Path | None = None,
    limit: int | None = None,
) -> list[Session]:
    """Scan agent session logs and return parsed Sessions.

    Args:
        base_dir: Override the default log directory.
        limit: Maximum number of sessions to parse.

    Returns:
        List of Sessions with normalized Events.
    """
    return scan_sessions(base_dir=base_dir, limit=limit)
