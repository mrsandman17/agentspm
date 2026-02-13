"""Core domain models for Agent Security Posture Management.

These models have ZERO dependencies on storage, CLI, or any framework.
They use the SSPM vocabulary: Session, Event, Policy, Alert, PostureScore.
"""

from __future__ import annotations

import re
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


class Severity(Enum):
    """Alert severity level. Maps to SSPM risk rating."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: Severity) -> bool:
        _order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return _order.index(self) < _order.index(other)


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


@dataclass
class RuleMatch:
    """Conditions that must ALL be true for a rule to fire on an event."""

    action_types: list[ActionType] | None = None
    """Only match events of these action types. None = match all."""

    elevated: bool | None = None
    """If set, only match events where elevated == this value."""

    command_pattern: str | None = None
    """Regex matched against event.target.command. None = skip check."""

    path_pattern: str | None = None
    """Regex matched against event.target.path. None = skip check."""

    def matches(self, event: Event) -> bool:
        """Return True iff ALL specified conditions match the event."""
        if self.action_types is not None and event.action_type not in self.action_types:
            return False
        if self.elevated is not None and event.elevated != self.elevated:
            return False
        if self.command_pattern is not None:
            if not event.target.command:
                return False
            if not re.search(self.command_pattern, event.target.command):
                return False
        if self.path_pattern is not None:
            if not event.target.path:
                return False
            if not re.search(self.path_pattern, event.target.path):
                return False
        return True


@dataclass
class PolicyRule:
    """A single rule within a Policy.

    Maps to SSPM "policy rule" — a specific prohibited or required behavior.
    """

    name: str
    description: str
    severity: Severity
    match: RuleMatch = field(default_factory=RuleMatch)


@dataclass
class Policy:
    """A named set of rules evaluated against agent sessions.

    Maps to SSPM "security policy" — what agents should and shouldn't do.
    """

    name: str
    description: str = ""
    rules: list[PolicyRule] = field(default_factory=list)


@dataclass(frozen=True)
class Alert:
    """A policy violation detected in an agent session.

    Maps to SSPM "misconfiguration alert" — a deviation from expected posture.
    """

    rule_name: str
    severity: Severity
    event: Event
    message: str
