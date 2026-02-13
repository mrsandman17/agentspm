"""Tests for out-of-directory rule matching."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agent_spm.domain.models import (
    ActionType,
    Alert,
    Event,
    Policy,
    PolicyRule,
    RuleMatch,
    Session,
    Severity,
    Target,
)
from agent_spm.engine.evaluator import evaluate
from agent_spm.policies.defaults import DEFAULT_POLICY


def _session(cwd: str | None = "/home/user/project", events: list[Event] | None = None) -> Session:
    return Session(
        session_id="test-session-id",
        model="claude-sonnet",
        cwd=cwd,
        started_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        events=events or [],
    )


def _file_event(path: str, action: ActionType = ActionType.FILE_READ) -> Event:
    return Event(
        session_id="test-session-id",
        timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        action_type=action,
        target=Target(tool_name="Read", path=path),
    )


_RULE = RuleMatch(
    action_types=[ActionType.FILE_READ, ActionType.FILE_WRITE],
    out_of_directory=True,
)


class TestOutOfDirectoryMatch:
    def test_path_outside_cwd_matches(self) -> None:
        event = _file_event("/etc/passwd")
        session = _session(cwd="/home/user/project")
        assert _RULE.matches(event, session=session) is True

    def test_path_inside_cwd_no_match(self) -> None:
        event = _file_event("/home/user/project/src/main.py")
        session = _session(cwd="/home/user/project")
        assert _RULE.matches(event, session=session) is False

    def test_path_equal_to_cwd_no_match(self) -> None:
        event = _file_event("/home/user/project")
        session = _session(cwd="/home/user/project")
        assert _RULE.matches(event, session=session) is False

    def test_path_none_no_match(self) -> None:
        event = Event(
            session_id="test-session-id",
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            action_type=ActionType.FILE_READ,
            target=Target(tool_name="Read", path=None),
        )
        session = _session(cwd="/home/user/project")
        assert _RULE.matches(event, session=session) is False

    def test_session_none_no_match(self) -> None:
        event = _file_event("/etc/passwd")
        assert _RULE.matches(event, session=None) is False

    def test_session_cwd_none_no_match(self) -> None:
        event = _file_event("/etc/passwd")
        session = _session(cwd=None)
        assert _RULE.matches(event, session=session) is False

    def test_action_type_filter_respected(self) -> None:
        # Only FILE_READ/FILE_WRITE — SHELL_EXEC should not match
        shell_event = Event(
            session_id="test-session-id",
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            action_type=ActionType.SHELL_EXEC,
            target=Target(tool_name="Bash", command="ls /etc"),
        )
        session = _session(cwd="/home/user/project")
        assert _RULE.matches(shell_event, session=session) is False

    def test_cwd_with_trailing_slash(self) -> None:
        event = _file_event("/home/user/project/file.txt")
        session = _session(cwd="/home/user/project/")
        assert _RULE.matches(event, session=session) is False

    def test_similar_prefix_is_outside(self) -> None:
        # /home/user/project-other is NOT inside /home/user/project
        event = _file_event("/home/user/project-other/file.txt")
        session = _session(cwd="/home/user/project")
        assert _RULE.matches(event, session=session) is True


class TestOutOfDirectoryIntegration:
    """Integration: out-of-directory rule fires through the evaluator."""

    def _ood_policy(self) -> Policy:
        return Policy(
            name="test",
            description="",
            rules=[
                PolicyRule(
                    name="out-of-directory-access",
                    description="Test",
                    severity=Severity.MEDIUM,
                    match=RuleMatch(
                        action_types=[ActionType.FILE_READ, ActionType.FILE_WRITE],
                        out_of_directory=True,
                    ),
                )
            ],
        )

    def test_evaluator_fires_for_outside_path(self) -> None:
        event = _file_event("/etc/passwd")
        session = _session(cwd="/home/user/project", events=[event])
        alerts = evaluate([session], [self._ood_policy()])
        assert len(alerts) == 1
        assert alerts[0].rule_name == "out-of-directory-access"

    def test_evaluator_silent_for_inside_path(self) -> None:
        event = _file_event("/home/user/project/README.md")
        session = _session(cwd="/home/user/project", events=[event])
        alerts = evaluate([session], [self._ood_policy()])
        assert len(alerts) == 0

    def test_default_policy_includes_ood_rule(self) -> None:
        names = [r.name for r in DEFAULT_POLICY.rules]
        assert "out-of-directory-access" in names

    def test_default_policy_ood_rule_fires(self) -> None:
        event = _file_event("/etc/hosts")
        session = _session(cwd="/home/user/project", events=[event])
        alerts = evaluate([session], [DEFAULT_POLICY])
        ood_alerts = [a for a in alerts if a.rule_name == "out-of-directory-access"]
        assert len(ood_alerts) == 1
