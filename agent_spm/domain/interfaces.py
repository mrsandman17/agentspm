"""Domain repository interfaces.

These are pure protocols — no storage implementation details leak into domain.
"""

from __future__ import annotations

from typing import Protocol

from agent_spm.domain.models import ActionType, Event, Session


class SessionRepository(Protocol):
    """Persist and query agent sessions and events."""

    def save_session(self, session: Session) -> None:
        """Persist a session and its events. Idempotent on session_id."""
        ...

    def get_session(self, session_id: str) -> Session | None:
        """Return a session by ID, with its events. None if not found."""
        ...

    def list_sessions(self) -> list[Session]:
        """Return all sessions, sorted newest-first by started_at."""
        ...

    def list_events(
        self,
        session_id: str | None = None,
        elevated_only: bool = False,
        action_type: ActionType | None = None,
    ) -> list[Event]:
        """Return events with optional filters."""
        ...
