"""Tests for the SQLite session repository."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agent_spm.domain.models import ActionType, Event, Session, Target
from agent_spm.storage.sqlite_repo import SQLiteSessionRepository


def _make_session(
    session_id: str = "sess-1",
    model: str = "claude-sonnet-4-5-20250929",
    events: list[Event] | None = None,
) -> Session:
    started = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    ended = datetime(2026, 1, 1, 10, 5, 0, tzinfo=UTC)
    return Session(
        session_id=session_id,
        model=model,
        cwd="/home/dev/project",
        started_at=started,
        ended_at=ended,
        events=events or [],
    )


def _make_event(
    session_id: str = "sess-1",
    action_type: ActionType = ActionType.FILE_READ,
    tool_name: str = "Read",
    path: str | None = "/app/main.py",
    command: str | None = None,
    elevated: bool = False,
) -> Event:
    return Event(
        session_id=session_id,
        timestamp=datetime(2026, 1, 1, 10, 1, 0, tzinfo=UTC),
        action_type=action_type,
        target=Target(tool_name=tool_name, path=path, command=command),
        elevated=elevated,
    )


@pytest.fixture()
def repo(tmp_path: Path) -> SQLiteSessionRepository:
    return SQLiteSessionRepository(db_path=tmp_path / "test.db")


class TestSaveAndRetrieve:
    def test_db_file_permissions_are_private(self, repo: SQLiteSessionRepository) -> None:
        if os.name != "posix":
            pytest.skip("POSIX permission bits not available")
        mode = repo._db_path.stat().st_mode & 0o777  # noqa: SLF001
        assert mode == 0o600

    def test_save_and_get_session(self, repo: SQLiteSessionRepository) -> None:
        session = _make_session()
        repo.save_session(session)
        result = repo.get_session("sess-1")
        assert result is not None
        assert result.session_id == "sess-1"
        assert result.model == "claude-sonnet-4-5-20250929"
        assert result.cwd == "/home/dev/project"

    def test_get_nonexistent_returns_none(self, repo: SQLiteSessionRepository) -> None:
        assert repo.get_session("no-such-id") is None

    def test_timestamps_round_trip(self, repo: SQLiteSessionRepository) -> None:
        session = _make_session()
        repo.save_session(session)
        result = repo.get_session("sess-1")
        assert result is not None
        assert result.started_at == session.started_at
        assert result.ended_at == session.ended_at

    def test_events_persisted_with_session(self, repo: SQLiteSessionRepository) -> None:
        event = _make_event()
        session = _make_session(events=[event])
        repo.save_session(session)
        result = repo.get_session("sess-1")
        assert result is not None
        assert len(result.events) == 1
        assert result.events[0].action_type == ActionType.FILE_READ
        assert result.events[0].target.path == "/app/main.py"

    def test_save_duplicate_is_idempotent(self, repo: SQLiteSessionRepository) -> None:
        session = _make_session()
        repo.save_session(session)
        repo.save_session(session)  # should not raise or duplicate
        sessions = repo.list_sessions()
        assert len(sessions) == 1


class TestListSessions:
    def test_list_empty(self, repo: SQLiteSessionRepository) -> None:
        assert repo.list_sessions() == []

    def test_list_multiple(self, repo: SQLiteSessionRepository) -> None:
        repo.save_session(_make_session("s1"))
        repo.save_session(_make_session("s2"))
        sessions = repo.list_sessions()
        assert len(sessions) == 2

    def test_list_sorted_newest_first(self, repo: SQLiteSessionRepository) -> None:
        older = Session(
            session_id="old",
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            ended_at=datetime(2026, 1, 1, 1, tzinfo=UTC),
        )
        newer = Session(
            session_id="new",
            started_at=datetime(2026, 1, 2, tzinfo=UTC),
            ended_at=datetime(2026, 1, 2, 1, tzinfo=UTC),
        )
        repo.save_session(older)
        repo.save_session(newer)
        sessions = repo.list_sessions()
        assert sessions[0].session_id == "new"
        assert sessions[1].session_id == "old"


class TestListEvents:
    @pytest.fixture()
    def repo_with_data(self, repo: SQLiteSessionRepository) -> SQLiteSessionRepository:
        read_event = _make_event("s1", ActionType.FILE_READ, "Read", "/app/main.py")
        write_event = _make_event("s1", ActionType.FILE_WRITE, "Edit", "/app/main.py")
        shell_event = _make_event("s1", ActionType.SHELL_EXEC, "Bash", None, "pytest tests/", False)
        elevated_event = _make_event(
            "s2", ActionType.SHELL_EXEC, "Bash", None, "sudo rm -rf /tmp", True
        )
        repo.save_session(_make_session("s1", events=[read_event, write_event, shell_event]))
        repo.save_session(_make_session("s2", events=[elevated_event]))
        return repo

    def test_list_all_events(self, repo_with_data: SQLiteSessionRepository) -> None:
        events = repo_with_data.list_events()
        assert len(events) == 4

    def test_filter_by_session(self, repo_with_data: SQLiteSessionRepository) -> None:
        events = repo_with_data.list_events(session_id="s1")
        assert len(events) == 3
        assert all(e.session_id == "s1" for e in events)

    def test_filter_elevated_only(self, repo_with_data: SQLiteSessionRepository) -> None:
        events = repo_with_data.list_events(elevated_only=True)
        assert len(events) == 1
        assert events[0].elevated is True
        assert events[0].session_id == "s2"

    def test_filter_by_action_type(self, repo_with_data: SQLiteSessionRepository) -> None:
        events = repo_with_data.list_events(action_type=ActionType.FILE_READ)
        assert len(events) == 1
        assert events[0].action_type == ActionType.FILE_READ

    def test_filter_combined(self, repo_with_data: SQLiteSessionRepository) -> None:
        events = repo_with_data.list_events(session_id="s1", action_type=ActionType.FILE_WRITE)
        assert len(events) == 1
        assert events[0].target.tool_name == "Edit"

    def test_event_fields_round_trip(self, repo_with_data: SQLiteSessionRepository) -> None:
        events = repo_with_data.list_events(elevated_only=True)
        e = events[0]
        assert e.target.command == "sudo rm -rf /tmp"
        assert e.target.tool_name == "Bash"
        assert e.target.path is None
