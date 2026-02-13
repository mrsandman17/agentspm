"""Core domain models for Agent Security Posture Management.

These models have ZERO dependencies on storage, CLI, or any framework.
They use the SSPM vocabulary: Session, Event, ActionType, Target.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ActionType(Enum):
    """What kind of action the agent performed.

    Maps to SSPM "permission type" — the category of resource access.
    """

    TOOL_CALL = "tool_call"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    SHELL_EXEC = "shell_exec"


@dataclass(frozen=True)
class Target:
    """What the agent acted on.

    Maps to SSPM "resource" — the specific file, command, or tool accessed.
    """

    tool_name: str
    """The tool that was invoked (e.g. 'Bash', 'Read', 'Write', 'Edit')."""

    path: str | None = None
    """File path, if applicable."""

    command: str | None = None
    """Shell command, if applicable (Bash tool)."""


@dataclass(frozen=True)
class Event:
    """A single agent action — the fundamental unit of observation.

    Maps to SSPM "event" — a recorded instance of resource access.
    """

    session_id: str
    timestamp: datetime
    action_type: ActionType
    target: Target
    elevated: bool = False
    """Whether this event involves elevated/risky permissions."""

    raw: dict[str, Any] = field(default_factory=dict, repr=False)
    """Original log entry for forensic reference."""


@dataclass
class Session:
    """An agent working session — a bounded period of agent activity.

    Maps to SSPM "user" — the identity being evaluated for security posture.
    """

    session_id: str
    model: str | None = None
    cwd: str | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    events: list[Event] = field(default_factory=list)

    @property
    def total_events(self) -> int:
        return len(self.events)

    @property
    def elevated_events(self) -> list[Event]:
        return [e for e in self.events if e.elevated]
