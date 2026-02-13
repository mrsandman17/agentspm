"""Tests for agent_spm/cli/sessions.py."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from agent_spm.cli.sessions import (
    _format_duration,
    _group_by_directory,
    _relative_time,
    _shorten_path,
    sessions,
)
from agent_spm.domain.models import ActionType, Event, Session, Target


def _dt(*args: int) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


def _session(
    session_id: str = "abc123",
    cwd: str | None = "/home/user/project",
    started_at: datetime | None = None,
) -> Session:
    return Session(
        session_id=session_id,
        model="claude-sonnet",
        cwd=cwd,
        started_at=started_at or _dt(2024, 1, 1, 12, 0, 0),
    )


class TestGroupByDirectory:
    def test_groups_by_cwd(self) -> None:
        s1 = _session("a", cwd="/home/user/proj-a")
        s2 = _session("b", cwd="/home/user/proj-b")
        s3 = _session("c", cwd="/home/user/proj-a")
        groups = _group_by_directory([s1, s2, s3])
        assert set(groups.keys()) == {"/home/user/proj-a", "/home/user/proj-b"}
        assert len(groups["/home/user/proj-a"]) == 2
        assert len(groups["/home/user/proj-b"]) == 1

    def test_none_cwd_grouped_under_unknown(self) -> None:
        s = _session("x", cwd=None)
        groups = _group_by_directory([s])
        assert "(unknown)" in groups

    def test_empty_list(self) -> None:
        assert _group_by_directory([]) == {}


class TestRelativeTime:
    def test_seconds(self) -> None:
        from datetime import timedelta
        dt = datetime.now(tz=timezone.utc) - timedelta(seconds=30)
        result = _relative_time(dt)
        assert "s ago" in result

    def test_minutes(self) -> None:
        from datetime import timedelta
        dt = datetime.now(tz=timezone.utc) - timedelta(minutes=5)
        assert "m ago" in _relative_time(dt)

    def test_hours(self) -> None:
        from datetime import timedelta
        dt = datetime.now(tz=timezone.utc) - timedelta(hours=3)
        assert "h ago" in _relative_time(dt)

    def test_days(self) -> None:
        from datetime import timedelta
        dt = datetime.now(tz=timezone.utc) - timedelta(days=2)
        assert "d ago" in _relative_time(dt)

    def test_naive_datetime(self) -> None:
        # Should not raise
        from datetime import timedelta
        dt = datetime.utcnow() - timedelta(hours=1)
        result = _relative_time(dt)
        assert "ago" in result


class TestFormatDuration:
    def test_seconds_only(self) -> None:
        start = _dt(2024, 1, 1, 12, 0, 0)
        end = _dt(2024, 1, 1, 12, 0, 45)
        assert _format_duration(start, end) == "45s"

    def test_minutes_and_seconds(self) -> None:
        start = _dt(2024, 1, 1, 12, 0, 0)
        end = _dt(2024, 1, 1, 12, 5, 23)
        assert _format_duration(start, end) == "5m 23s"

    def test_hours_and_minutes(self) -> None:
        start = _dt(2024, 1, 1, 10, 0, 0)
        end = _dt(2024, 1, 1, 12, 30, 0)
        assert _format_duration(start, end) == "2h 30m"

    def test_no_start_returns_question_mark(self) -> None:
        assert _format_duration(None, None) == "?"


class TestShortenPath:
    def test_replaces_home(self, tmp_path) -> None:
        import os
        home = os.path.expanduser("~")
        result = _shorten_path(home + "/Development/project")
        assert result.startswith("~")

    def test_non_home_path_unchanged(self) -> None:
        result = _shorten_path("/etc/passwd")
        assert result == "/etc/passwd"


class TestSessionsCLI:
    def _make_sessions(self) -> list[Session]:
        event = Event(
            session_id="abc123def456",
            timestamp=_dt(2024, 1, 1, 12, 0, 0),
            action_type=ActionType.FILE_READ,
            target=Target(tool_name="Read", path="/home/user/project/file.py"),
        )
        return [
            Session(
                session_id="abc123def456",
                model="claude-sonnet",
                cwd="/home/user/project",
                started_at=_dt(2024, 1, 1, 12, 0, 0),
                ended_at=_dt(2024, 1, 1, 12, 5, 0),
                events=[event],
            )
        ]

    def test_directory_overview(self) -> None:
        runner = CliRunner()
        with patch("agent_spm.cli.sessions.scan_sessions", return_value=self._make_sessions()):
            result = runner.invoke(sessions, [])
        assert result.exit_code == 0
        assert "/home/user/project" in result.output or "project" in result.output

    def test_empty_sessions(self) -> None:
        runner = CliRunner()
        with patch("agent_spm.cli.sessions.scan_sessions", return_value=[]):
            result = runner.invoke(sessions, [])
        assert result.exit_code == 0
        assert "No sessions found" in result.output

    def test_session_detail_by_id(self) -> None:
        runner = CliRunner()
        with patch("agent_spm.cli.sessions.scan_sessions", return_value=self._make_sessions()):
            result = runner.invoke(sessions, ["abc123"])
        assert result.exit_code == 0
        assert "abc123def456" in result.output

    def test_session_detail_not_found(self) -> None:
        runner = CliRunner()
        with patch("agent_spm.cli.sessions.scan_sessions", return_value=self._make_sessions()):
            result = runner.invoke(sessions, ["zzz999"])
        assert result.exit_code == 0
        assert "No session found" in result.output

    def test_multiple_directories(self) -> None:
        runner = CliRunner()
        s1 = Session("aaa", cwd="/dir-a", started_at=_dt(2024, 1, 1, 12, 0))
        s2 = Session("bbb", cwd="/dir-b", started_at=_dt(2024, 1, 1, 13, 0))
        with patch("agent_spm.cli.sessions.scan_sessions", return_value=[s1, s2]):
            result = runner.invoke(sessions, [])
        assert result.exit_code == 0
