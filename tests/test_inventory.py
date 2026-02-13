"""Tests for the inventory engine."""

from __future__ import annotations

from datetime import UTC, datetime

from agent_spm.domain.models import ActionType, Event, Session, Target
from agent_spm.engine.inventory import build_inventory


def _event(
    session_id: str,
    tool_name: str,
    action_type: ActionType,
    elevated: bool = False,
) -> Event:
    return Event(
        session_id=session_id,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        action_type=action_type,
        target=Target(tool_name=tool_name),
        elevated=elevated,
    )


def _session(session_id: str, *events: Event) -> Session:
    return Session(session_id=session_id, events=list(events))


class TestBuildInventory:
    def test_empty_sessions(self) -> None:
        result = build_inventory([])
        assert result == []

    def test_sessions_with_no_events(self) -> None:
        result = build_inventory([_session("s1"), _session("s2")])
        assert result == []

    def test_single_tool_one_session(self) -> None:
        s = _session("s1", _event("s1", "Read", ActionType.FILE_READ))
        result = build_inventory([s])
        assert len(result) == 1
        entry = result[0]
        assert entry.tool_name == "Read"
        assert entry.action_type == ActionType.FILE_READ
        assert entry.call_count == 1
        assert entry.session_count == 1
        assert entry.elevated_count == 0

    def test_call_count_aggregated(self) -> None:
        s = _session(
            "s1",
            _event("s1", "Read", ActionType.FILE_READ),
            _event("s1", "Read", ActionType.FILE_READ),
            _event("s1", "Read", ActionType.FILE_READ),
        )
        result = build_inventory([s])
        assert len(result) == 1
        assert result[0].call_count == 3

    def test_session_count_deduplicates_across_sessions(self) -> None:
        s1 = _session("s1", _event("s1", "Bash", ActionType.SHELL_EXEC))
        s2 = _session("s2", _event("s2", "Bash", ActionType.SHELL_EXEC))
        result = build_inventory([s1, s2])
        assert len(result) == 1
        assert result[0].session_count == 2
        assert result[0].call_count == 2

    def test_elevated_count(self) -> None:
        s = _session(
            "s1",
            _event("s1", "Bash", ActionType.SHELL_EXEC, elevated=False),
            _event("s1", "Bash", ActionType.SHELL_EXEC, elevated=True),
            _event("s1", "Bash", ActionType.SHELL_EXEC, elevated=True),
        )
        result = build_inventory([s])
        assert result[0].elevated_count == 2

    def test_multiple_tools(self) -> None:
        s = _session(
            "s1",
            _event("s1", "Read", ActionType.FILE_READ),
            _event("s1", "Edit", ActionType.FILE_WRITE),
            _event("s1", "Bash", ActionType.SHELL_EXEC),
        )
        result = build_inventory([s])
        assert len(result) == 3
        tool_names = {e.tool_name for e in result}
        assert tool_names == {"Read", "Edit", "Bash"}

    def test_sorted_by_call_count_descending(self) -> None:
        s = _session(
            "s1",
            _event("s1", "Read", ActionType.FILE_READ),
            _event("s1", "Read", ActionType.FILE_READ),
            _event("s1", "Read", ActionType.FILE_READ),
            _event("s1", "Bash", ActionType.SHELL_EXEC),
            _event("s1", "Bash", ActionType.SHELL_EXEC),
            _event("s1", "Edit", ActionType.FILE_WRITE),
        )
        result = build_inventory([s])
        assert result[0].tool_name == "Read"
        assert result[1].tool_name == "Bash"
        assert result[2].tool_name == "Edit"
