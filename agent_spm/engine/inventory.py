"""Inventory engine — aggregate tool usage across sessions.

Maps to SSPM "application inventory": what tools (SaaS apps) has the agent used,
how often, and were any of those uses elevated/risky?
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from agent_spm.domain.models import ActionType, Session


@dataclass
class ToolInventoryEntry:
    """Aggregated usage stats for a single tool across all scanned sessions."""

    tool_name: str
    action_type: ActionType
    call_count: int
    session_count: int
    elevated_count: int


def build_inventory(sessions: list[Session]) -> list[ToolInventoryEntry]:
    """Aggregate tool usage across sessions into inventory entries.

    Returns entries sorted by call_count descending.
    """
    # tool_name -> {call_count, session_ids, elevated_count, action_type}
    stats: dict[str, dict] = defaultdict(
        lambda: {"call_count": 0, "session_ids": set(), "elevated_count": 0, "action_type": None}
    )

    for session in sessions:
        for event in session.events:
            name = event.target.tool_name
            s = stats[name]
            s["call_count"] += 1
            s["session_ids"].add(event.session_id)
            s["elevated_count"] += int(event.elevated)
            if s["action_type"] is None:
                s["action_type"] = event.action_type

    entries = [
        ToolInventoryEntry(
            tool_name=name,
            action_type=s["action_type"],
            call_count=s["call_count"],
            session_count=len(s["session_ids"]),
            elevated_count=s["elevated_count"],
        )
        for name, s in stats.items()
    ]

    entries.sort(key=lambda e: e.call_count, reverse=True)
    return entries
