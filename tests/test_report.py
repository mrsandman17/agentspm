"""Tests for the report generation engine."""

from __future__ import annotations

from datetime import UTC, datetime

from agent_spm.domain.models import (
    ActionType,
    Alert,
    Event,
    Policy,
    Session,
    Severity,
    Target,
)
from agent_spm.engine.report import Report, generate_report, render_markdown


def _ts() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _event(session_id: str = "s1", elevated: bool = False) -> Event:
    return Event(
        session_id=session_id,
        timestamp=_ts(),
        action_type=ActionType.SHELL_EXEC,
        target=Target(tool_name="Bash", command="pytest tests/"),
        elevated=elevated,
    )


def _alert(severity: Severity, rule_name: str = "test-rule", session_id: str = "s1") -> Alert:
    return Alert(
        rule_name=rule_name,
        severity=severity,
        event=_event(session_id),
        message="test alert",
    )


def _session(*events: Event, session_id: str = "s1") -> Session:
    return Session(session_id=session_id, events=list(events) or [_event(session_id)])


def _policy(name: str = "test-policy") -> Policy:
    return Policy(name=name, description="A test policy")


class TestGenerateReport:
    def test_empty_inputs_returns_perfect_score(self) -> None:
        report = generate_report([], [], [_policy()])
        assert report.posture.score == 100
        assert report.posture.grade == "A"

    def test_captures_policy_names(self) -> None:
        report = generate_report([], [], [_policy("p1"), _policy("p2")])
        assert report.policy_names == ["p1", "p2"]

    def test_generated_at_is_set(self) -> None:
        report = generate_report([], [], [_policy()])
        assert isinstance(report.generated_at, datetime)

    def test_posture_reflects_alerts(self) -> None:
        sessions = [_session()]
        alerts = [_alert(Severity.CRITICAL)]
        report = generate_report(sessions, alerts, [_policy()])
        assert report.posture.score == 80

    def test_top_alerts_sorted_critical_first(self) -> None:
        alerts = [
            _alert(Severity.LOW, "low-rule"),
            _alert(Severity.CRITICAL, "crit-rule"),
            _alert(Severity.HIGH, "high-rule"),
        ]
        report = generate_report([_session()], alerts, [_policy()])
        severities = [a.severity for a in report.top_alerts]
        assert severities[0] == Severity.CRITICAL
        assert severities[1] == Severity.HIGH
        assert severities[2] == Severity.LOW

    def test_top_n_limits_alerts(self) -> None:
        alerts = [_alert(Severity.HIGH) for _ in range(20)]
        report = generate_report([_session()], alerts, [_policy()], top_n=5)
        assert len(report.top_alerts) == 5

    def test_top_n_default_is_10(self) -> None:
        alerts = [_alert(Severity.HIGH) for _ in range(20)]
        report = generate_report([_session()], alerts, [_policy()])
        assert len(report.top_alerts) == 10

    def test_elevated_events_collected(self) -> None:
        normal = _event("s1", elevated=False)
        elevated = _event("s1", elevated=True)
        session = Session("s1", events=[normal, elevated])
        report = generate_report([session], [], [_policy()])
        assert len(report.elevated_events) == 1
        assert report.elevated_events[0].elevated is True

    def test_elevated_events_limited_by_top_n(self) -> None:
        events = [_event("s1", elevated=True) for _ in range(20)]
        session = Session("s1", events=events)
        report = generate_report([session], [], [_policy()], top_n=5)
        assert len(report.elevated_events) == 5

    def test_total_sessions_and_events(self) -> None:
        s1 = Session("s1", events=[_event("s1"), _event("s1")])
        s2 = Session("s2", events=[_event("s2")])
        report = generate_report([s1, s2], [], [_policy()])
        assert report.posture.total_sessions == 2
        assert report.posture.total_events == 3


class TestRenderMarkdown:
    def _report(self) -> Report:
        sessions = [_session()]
        alerts = [
            _alert(Severity.CRITICAL, "force-push"),
            _alert(Severity.HIGH, "sudo-cmd"),
        ]
        return generate_report(sessions, alerts, [_policy("default")])

    def test_contains_title(self) -> None:
        md = render_markdown(self._report())
        assert "# Agent Security Posture Report" in md

    def test_contains_score(self) -> None:
        md = render_markdown(self._report())
        assert "/100" in md

    def test_contains_grade(self) -> None:
        md = render_markdown(self._report())
        # 1 critical=−20, 1 high=−10 → score=70 → grade C
        assert "Grade:" in md

    def test_contains_severity_breakdown_header(self) -> None:
        md = render_markdown(self._report())
        assert "## Alert Breakdown" in md

    def test_contains_top_alerts_header(self) -> None:
        md = render_markdown(self._report())
        assert "## Top Policy Violations" in md

    def test_contains_rule_name_in_violations(self) -> None:
        md = render_markdown(self._report())
        assert "force-push" in md
        assert "sudo-cmd" in md

    def test_contains_elevated_events_header(self) -> None:
        elevated = _event("s1", elevated=True)
        session = Session("s1", events=[elevated])
        report = generate_report([session], [], [_policy()])
        md = render_markdown(report)
        assert "## Elevated Events" in md

    def test_no_elevated_events_section_when_none(self) -> None:
        report = generate_report([_session()], [], [_policy()])
        md = render_markdown(report)
        assert "## Elevated Events" not in md

    def test_contains_policy_names(self) -> None:
        report = generate_report([], [], [_policy("my-policy")])
        md = render_markdown(report)
        assert "my-policy" in md

    def test_contains_generated_at(self) -> None:
        md = render_markdown(self._report())
        assert "Generated:" in md

    def test_no_violations_when_empty(self) -> None:
        report = generate_report([], [], [_policy()])
        md = render_markdown(report)
        assert "No policy violations detected" in md

    def test_redacts_sensitive_command_in_markdown(self) -> None:
        event = Event(
            session_id="s1",
            timestamp=_ts(),
            action_type=ActionType.SHELL_EXEC,
            target=Target(tool_name="Bash", command="curl -H 'Authorization=Bearer super-secret'"),
            elevated=True,
        )
        alert = Alert(
            rule_name="token-leak",
            severity=Severity.HIGH,
            event=event,
            message="test",
        )
        report = generate_report([Session("s1", events=[event])], [alert], [_policy()])
        md = render_markdown(report)
        assert "super-secret" not in md
        assert "[REDACTED]" in md
