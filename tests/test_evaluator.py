"""Tests for the policy evaluator."""

from __future__ import annotations

from datetime import UTC, datetime

from agent_spm.domain.models import (
    ActionType,
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


def _event(
    session_id: str = "s1",
    action_type: ActionType = ActionType.SHELL_EXEC,
    command: str | None = "pytest tests/",
    path: str | None = None,
    elevated: bool = False,
) -> Event:
    return Event(
        session_id=session_id,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        action_type=action_type,
        target=Target(tool_name="Bash", command=command, path=path),
        elevated=elevated,
    )


def _rule(
    name: str,
    severity: Severity = Severity.HIGH,
    **match_kwargs,
) -> PolicyRule:
    return PolicyRule(name=name, description="", severity=severity, match=RuleMatch(**match_kwargs))


def _policy(*rules: PolicyRule, name: str = "test") -> Policy:
    return Policy(name=name, rules=list(rules))


class TestEvaluate:
    def test_no_policies_returns_no_alerts(self) -> None:
        session = Session("s1", events=[_event(elevated=True)])
        alerts = evaluate([session], [])
        assert alerts == []

    def test_no_sessions_returns_no_alerts(self) -> None:
        policy = _policy(_rule("r", elevated=True))
        alerts = evaluate([], [policy])
        assert alerts == []

    def test_matching_rule_generates_alert(self) -> None:
        policy = _policy(_rule("elevated-shell", elevated=True))
        session = Session("s1", events=[_event(elevated=True)])
        alerts = evaluate([session], [policy])
        assert len(alerts) == 1
        assert alerts[0].rule_name == "elevated-shell"

    def test_non_matching_event_no_alert(self) -> None:
        policy = _policy(_rule("elevated-shell", elevated=True))
        session = Session("s1", events=[_event(elevated=False)])
        alerts = evaluate([session], [policy])
        assert alerts == []

    def test_alert_has_correct_severity(self) -> None:
        policy = _policy(_rule("critical-rule", severity=Severity.CRITICAL, elevated=True))
        session = Session("s1", events=[_event(elevated=True)])
        alerts = evaluate([session], [policy])
        assert alerts[0].severity == Severity.CRITICAL

    def test_alert_references_triggering_event(self) -> None:
        event = _event(elevated=True)
        policy = _policy(_rule("r", elevated=True))
        session = Session("s1", events=[event])
        alerts = evaluate([session], [policy])
        assert alerts[0].event is event

    def test_multiple_rules_multiple_alerts(self) -> None:
        r1 = _rule("r1", elevated=True)
        r2 = _rule("r2", action_types=[ActionType.SHELL_EXEC])
        policy = _policy(r1, r2)
        event = _event(elevated=True, action_type=ActionType.SHELL_EXEC)
        session = Session("s1", events=[event])
        alerts = evaluate([session], [policy])
        assert len(alerts) == 2

    def test_multiple_sessions(self) -> None:
        policy = _policy(_rule("r", elevated=True))
        s1 = Session("s1", events=[_event(elevated=True)])
        s2 = Session("s2", events=[_event(elevated=True)])
        alerts = evaluate([s1, s2], [policy])
        assert len(alerts) == 2

    def test_multiple_policies(self) -> None:
        p1 = _policy(_rule("from-p1", elevated=True), name="p1")
        p2 = _policy(_rule("from-p2", elevated=True), name="p2")
        session = Session("s1", events=[_event(elevated=True)])
        alerts = evaluate([session], [p1, p2])
        assert len(alerts) == 2
        names = {a.rule_name for a in alerts}
        assert names == {"from-p1", "from-p2"}


class TestDefaultPolicy:
    """Smoke tests against the built-in default policy."""

    def test_default_policy_has_rules(self) -> None:
        assert len(DEFAULT_POLICY.rules) > 0

    def test_sudo_triggers_alert(self) -> None:
        event = Event(
            session_id="s1",
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            action_type=ActionType.SHELL_EXEC,
            target=Target(tool_name="Bash", command="sudo apt install nginx"),
            elevated=True,
        )
        alerts = evaluate([Session("s1", events=[event])], [DEFAULT_POLICY])
        assert len(alerts) > 0

    def test_safe_event_no_alert(self) -> None:
        event = Event(
            session_id="s1",
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            action_type=ActionType.SHELL_EXEC,
            target=Target(tool_name="Bash", command="pytest tests/"),
            elevated=False,
        )
        alerts = evaluate([Session("s1", events=[event])], [DEFAULT_POLICY])
        assert alerts == []

    def test_force_push_triggers_alert(self) -> None:
        event = Event(
            session_id="s1",
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            action_type=ActionType.SHELL_EXEC,
            target=Target(tool_name="Bash", command="git push --force origin main"),
            elevated=True,
        )
        alerts = evaluate([Session("s1", events=[event])], [DEFAULT_POLICY])
        assert len(alerts) > 0

    def test_env_file_read_triggers_alert(self) -> None:
        event = Event(
            session_id="s1",
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            action_type=ActionType.FILE_READ,
            target=Target(tool_name="Read", path="/app/.env"),
            elevated=True,
        )
        alerts = evaluate([Session("s1", events=[event])], [DEFAULT_POLICY])
        assert len(alerts) > 0
