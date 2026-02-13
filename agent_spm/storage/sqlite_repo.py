"""SQLite-backed session repository.

Schema:
  sessions — one row per session (session_id PK)
  events   — one row per event (FK → sessions)

The raw dict is NOT stored — only structured fields are persisted.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from agent_spm.domain.models import ActionType, Event, Session, Target

_DEFAULT_DB = Path.home() / ".claude" / "agent_spm.db"

_DDL = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id  TEXT PRIMARY KEY,
    model       TEXT,
    cwd         TEXT,
    started_at  TEXT,
    ended_at    TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT    NOT NULL,
    timestamp   TEXT    NOT NULL,
    action_type TEXT    NOT NULL,
    tool_name   TEXT    NOT NULL,
    path        TEXT,
    command     TEXT,
    elevated    INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_elevated ON events(elevated);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(action_type);
"""


def _dt_to_str(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.isoformat()


def _str_to_dt(s: str | None) -> datetime | None:
    if s is None:
        return None
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


class SQLiteSessionRepository:
    """SQLite implementation of the SessionRepository protocol."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or _DEFAULT_DB
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_DDL)

    def save_session(self, session: Session) -> None:
        """Persist session and its events. Idempotent on session_id."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO sessions (session_id, model, cwd, started_at, ended_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    model      = excluded.model,
                    cwd        = excluded.cwd,
                    started_at = excluded.started_at,
                    ended_at   = excluded.ended_at
                """,
                (
                    session.session_id,
                    session.model,
                    session.cwd,
                    _dt_to_str(session.started_at),
                    _dt_to_str(session.ended_at),
                ),
            )
            # Delete existing events for this session before re-inserting
            conn.execute("DELETE FROM events WHERE session_id = ?", (session.session_id,))
            for event in session.events:
                conn.execute(
                    """
                    INSERT INTO events
                        (session_id, timestamp, action_type, tool_name, path, command, elevated)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.session_id,
                        _dt_to_str(event.timestamp),
                        event.action_type.value,
                        event.target.tool_name,
                        event.target.path,
                        event.target.command,
                        int(event.elevated),
                    ),
                )

    def get_session(self, session_id: str) -> Session | None:
        """Return session with events, or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if row is None:
                return None
            session = self._row_to_session(row)
            session.events = self._fetch_events(conn, session_id=session_id)
            return session

    def list_sessions(self) -> list[Session]:
        """Return all sessions, newest-first, with events."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY started_at DESC NULLS LAST"
            ).fetchall()
            sessions = []
            for row in rows:
                s = self._row_to_session(row)
                s.events = self._fetch_events(conn, session_id=s.session_id)
                sessions.append(s)
            return sessions

    def list_events(
        self,
        session_id: str | None = None,
        elevated_only: bool = False,
        action_type: ActionType | None = None,
    ) -> list[Event]:
        """Return events with optional filters."""
        query = "SELECT * FROM events WHERE 1=1"
        params: list[object] = []

        if session_id is not None:
            query += " AND session_id = ?"
            params.append(session_id)
        if elevated_only:
            query += " AND elevated = 1"
        if action_type is not None:
            query += " AND action_type = ?"
            params.append(action_type.value)

        query += " ORDER BY timestamp ASC"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_event(row) for row in rows]

    @staticmethod
    def _row_to_session(row: sqlite3.Row) -> Session:
        return Session(
            session_id=row["session_id"],
            model=row["model"],
            cwd=row["cwd"],
            started_at=_str_to_dt(row["started_at"]),
            ended_at=_str_to_dt(row["ended_at"]),
        )

    @staticmethod
    def _fetch_events(conn: sqlite3.Connection, session_id: str) -> list[Event]:
        rows = conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        ).fetchall()
        return [SQLiteSessionRepository._row_to_event(row) for row in rows]

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Event:
        return Event(
            session_id=row["session_id"],
            timestamp=_str_to_dt(row["timestamp"]),  # type: ignore[arg-type]
            action_type=ActionType(row["action_type"]),
            target=Target(
                tool_name=row["tool_name"],
                path=row["path"],
                command=row["command"],
            ),
            elevated=bool(row["elevated"]),
        )
