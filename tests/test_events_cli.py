"""Tests for events CLI behavior."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

from click.testing import CliRunner

from agent_spm.cli.events import events
from agent_spm.domain.models import ActionType, Event, Session, Target


def _event(session_id: str, hour: int, command: str) -> Event:
    return Event(
        session_id=session_id,
        timestamp=datetime(2026, 1, 1, hour, 0, 0, tzinfo=UTC),
        action_type=ActionType.SHELL_EXEC,
        target=Target(tool_name="Bash", command=command),
    )


def test_events_sorted_globally_by_timestamp() -> None:
    s1 = Session("s1", events=[_event("s1", 13, "echo later")])
    s2 = Session("s2", events=[_event("s2", 12, "echo earlier")])

    runner = CliRunner()
    with patch("agent_spm.cli.events.scan_sessions", return_value=[s1, s2]):
        result = runner.invoke(events, [])
    assert result.exit_code == 0
    assert result.output.index("12:00:00") < result.output.index("13:00:00")


def test_events_limit_does_not_change_scan_scope() -> None:
    runner = CliRunner()
    with patch("agent_spm.cli.events.scan_sessions", return_value=[]) as mocked_scan:
        result = runner.invoke(events, ["--limit", "2"])
        assert result.exit_code == 0
        mocked_scan.assert_called_once_with(base_dir=None, limit=None)


def test_session_limit_is_applied_to_scan_sessions() -> None:
    runner = CliRunner()
    with patch("agent_spm.cli.events.scan_sessions", return_value=[]) as mocked_scan:
        result = runner.invoke(events, ["--session-limit", "2"])
        assert result.exit_code == 0
        mocked_scan.assert_called_once_with(base_dir=None, limit=2)


def test_events_output_redacts_sensitive_command_values() -> None:
    session = Session("s1", events=[_event("s1", 12, "deploy --token secret-token")])
    runner = CliRunner()
    with patch("agent_spm.cli.events.scan_sessions", return_value=[session]):
        result = runner.invoke(events, [])
    assert result.exit_code == 0
    assert "secret-token" not in result.output
    assert "[REDACTED]" in result.output
