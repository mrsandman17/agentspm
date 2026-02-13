"""Tests for policy loading and rule matching."""

from __future__ import annotations

import textwrap
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agent_spm.domain.models import (
    ActionType,
    Event,
    PolicyRule,
    RuleMatch,
    Session,
    Severity,
    Target,
)
from agent_spm.policies.loader import load_policy, load_policy_dir

# ─── Fixtures ─────────────────────────────────────────────────────────────────


def _event(
    session_id: str = "s1",
    action_type: ActionType = ActionType.SHELL_EXEC,
    tool_name: str = "Bash",
    command: str | None = None,
    path: str | None = None,
    elevated: bool = False,
) -> Event:
    return Event(
        session_id=session_id,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        action_type=action_type,
        target=Target(tool_name=tool_name, command=command, path=path),
        elevated=elevated,
    )


def _session(*events: Event, session_id: str = "s1") -> Session:
    return Session(session_id=session_id, events=list(events))


# ─── RuleMatch tests ──────────────────────────────────────────────────────────


class TestRuleMatch:
    def test_match_elevated_true_matches_elevated_event(self) -> None:
        rule = PolicyRule(
            name="r",
            description="",
            severity=Severity.HIGH,
            match=RuleMatch(elevated=True),
        )
        event = _event(elevated=True)
        assert rule.match.matches(event)

    def test_match_elevated_true_does_not_match_non_elevated(self) -> None:
        rule = PolicyRule(
            name="r",
            description="",
            severity=Severity.HIGH,
            match=RuleMatch(elevated=True),
        )
        event = _event(elevated=False)
        assert not rule.match.matches(event)

    def test_match_action_type_filter(self) -> None:
        match = RuleMatch(action_types=[ActionType.SHELL_EXEC])
        assert match.matches(_event(action_type=ActionType.SHELL_EXEC))
        assert not match.matches(_event(action_type=ActionType.FILE_READ))

    def test_match_command_pattern(self) -> None:
        match = RuleMatch(command_pattern=r"git push .*(--force|-f)")
        assert match.matches(_event(command="git push --force origin main"))
        assert match.matches(_event(command="git push -f origin main"))
        assert not match.matches(_event(command="git push origin main"))

    def test_match_path_pattern(self) -> None:
        match = RuleMatch(
            action_types=[ActionType.FILE_READ],
            path_pattern=r"\.env",
        )
        assert match.matches(
            _event(action_type=ActionType.FILE_READ, path="/app/.env", command=None)
        )
        assert not match.matches(
            _event(action_type=ActionType.FILE_READ, path="/app/main.py", command=None)
        )

    def test_all_conditions_must_match(self) -> None:
        match = RuleMatch(
            action_types=[ActionType.SHELL_EXEC],
            elevated=True,
            command_pattern=r"sudo",
        )
        # All three conditions met
        assert match.matches(
            _event(action_type=ActionType.SHELL_EXEC, command="sudo apt install", elevated=True)
        )
        # Wrong action type
        assert not match.matches(
            _event(action_type=ActionType.FILE_READ, command="sudo apt install", elevated=True)
        )
        # Not elevated
        assert not match.matches(
            _event(action_type=ActionType.SHELL_EXEC, command="sudo apt install", elevated=False)
        )
        # No sudo in command
        assert not match.matches(
            _event(action_type=ActionType.SHELL_EXEC, command="pytest tests/", elevated=True)
        )

    def test_empty_match_matches_all_events(self) -> None:
        match = RuleMatch()
        assert match.matches(_event())
        assert match.matches(
            _event(action_type=ActionType.FILE_READ, path="/app/main.py", command=None)
        )


# ─── Policy YAML loading ──────────────────────────────────────────────────────


class TestLoadPolicy:
    def test_load_minimal_policy(self, tmp_path: Path) -> None:
        f = tmp_path / "minimal.yml"
        f.write_text(
            textwrap.dedent("""
            name: minimal
            description: Minimal test policy
            rules: []
        """)
        )
        policy = load_policy(f)
        assert policy.name == "minimal"
        assert policy.description == "Minimal test policy"
        assert policy.rules == []

    def test_load_policy_with_rule(self, tmp_path: Path) -> None:
        f = tmp_path / "policy.yml"
        f.write_text(
            textwrap.dedent("""
            name: test-policy
            rules:
              - name: no-elevated
                description: No elevated commands
                severity: high
                match:
                  elevated: true
        """)
        )
        policy = load_policy(f)
        assert len(policy.rules) == 1
        rule = policy.rules[0]
        assert rule.name == "no-elevated"
        assert rule.severity == Severity.HIGH
        assert rule.match.elevated is True

    def test_load_policy_with_action_types(self, tmp_path: Path) -> None:
        f = tmp_path / "policy.yml"
        f.write_text(
            textwrap.dedent("""
            name: test-policy
            rules:
              - name: shell-only
                description: Shell commands only
                severity: medium
                match:
                  action_types: [shell_exec]
        """)
        )
        policy = load_policy(f)
        rule = policy.rules[0]
        assert rule.match.action_types == [ActionType.SHELL_EXEC]

    def test_load_policy_with_command_pattern(self, tmp_path: Path) -> None:
        f = tmp_path / "policy.yml"
        f.write_text(
            textwrap.dedent("""
            name: test-policy
            rules:
              - name: force-push
                description: Force push
                severity: critical
                match:
                  action_types: [shell_exec]
                  command_pattern: "git push .*(--force|-f)"
        """)
        )
        policy = load_policy(f)
        rule = policy.rules[0]
        assert rule.match.command_pattern == "git push .*(--force|-f)"
        assert rule.severity == Severity.CRITICAL

    def test_load_nonexistent_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_policy(tmp_path / "nonexistent.yml")

    def test_load_policy_dir(self, tmp_path: Path) -> None:
        (tmp_path / "a.yml").write_text("name: a\nrules: []\n")
        (tmp_path / "b.yml").write_text("name: b\nrules: []\n")
        (tmp_path / "not_a_policy.txt").write_text("ignored")
        policies = load_policy_dir(tmp_path)
        assert len(policies) == 2
        names = {p.name for p in policies}
        assert names == {"a", "b"}

    def test_load_policy_dir_empty(self, tmp_path: Path) -> None:
        assert load_policy_dir(tmp_path) == []

    def test_load_policy_dir_nonexistent(self, tmp_path: Path) -> None:
        assert load_policy_dir(tmp_path / "missing") == []
