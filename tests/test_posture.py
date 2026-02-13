"""Tests for the posture scoring engine."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agent_spm.domain.models import (
    ActionType,
    Alert,
    Event,
    Session,
    Severity,
    Target,
)
from agent_spm.engine.posture import calculate_posture


def _event(session_id: str = "s1") -> Event:
    return Event(
        session_id=session_id,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        action_type=ActionType.SHELL_EXEC,
        target=Target(tool_name="Bash", command="pytest tests/"),
    )


def _alert(severity: Severity, session_id: str = "s1") -> Alert:
    return Alert(
        rule_name="test-rule",
        severity=severity,
        event=_event(session_id),
        message="test alert",
    )


def _session(*events: Event, session_id: str = "s1") -> Session:
    return Session(session_id=session_id, events=list(events) or [_event(session_id)])


class TestCalculatePosture:
    def test_no_sessions_no_alerts(self) -> None:
        score = calculate_posture([], [])
        assert score.score == 100
        assert score.grade == "A"
        assert score.total_sessions == 0
        assert score.total_events == 0
        assert score.total_alerts == 0

    def test_sessions_with_no_alerts_is_perfect(self) -> None:
        sessions = [_session(), _session(session_id="s2")]
        score = calculate_posture(sessions, [])
        assert score.score == 100
        assert score.grade == "A"

    def test_single_critical_alert_deducts_20(self) -> None:
        sessions = [_session()]
        alerts = [_alert(Severity.CRITICAL)]
        score = calculate_posture(sessions, alerts)
        assert score.score == 80

    def test_single_high_alert_deducts_10(self) -> None:
        score = calculate_posture([_session()], [_alert(Severity.HIGH)])
        assert score.score == 90

    def test_single_medium_alert_deducts_3(self) -> None:
        score = calculate_posture([_session()], [_alert(Severity.MEDIUM)])
        assert score.score == 97

    def test_single_low_alert_deducts_1(self) -> None:
        score = calculate_posture([_session()], [_alert(Severity.LOW)])
        assert score.score == 99

    def test_critical_deduction_capped_at_40(self) -> None:
        alerts = [_alert(Severity.CRITICAL) for _ in range(10)]
        score = calculate_posture([_session()], alerts)
        # max deduction for critical is 40, so 100 - 40 = 60
        assert score.score == 60

    def test_high_deduction_capped_at_30(self) -> None:
        alerts = [_alert(Severity.HIGH) for _ in range(10)]
        score = calculate_posture([_session()], alerts)
        # max 30, so 100 - 30 = 70
        assert score.score == 70

    def test_medium_deduction_capped_at_15(self) -> None:
        alerts = [_alert(Severity.MEDIUM) for _ in range(10)]
        score = calculate_posture([_session()], alerts)
        # 10 * 3 = 30, capped at 15, so 100 - 15 = 85
        assert score.score == 85

    def test_low_deduction_capped_at_5(self) -> None:
        alerts = [_alert(Severity.LOW) for _ in range(10)]
        score = calculate_posture([_session()], alerts)
        # 10 * 1 = 10, capped at 5, so 100 - 5 = 95
        assert score.score == 95

    def test_combined_deductions_do_not_go_below_zero(self) -> None:
        alerts = (
            [_alert(Severity.CRITICAL) for _ in range(10)]
            + [_alert(Severity.HIGH) for _ in range(10)]
            + [_alert(Severity.MEDIUM) for _ in range(10)]
            + [_alert(Severity.LOW) for _ in range(10)]
        )
        score = calculate_posture([_session()], alerts)
        # max deductions: 40 + 30 + 15 + 5 = 90, so score = 10
        assert score.score == 10
        assert score.score >= 0

    def test_total_sessions_count(self) -> None:
        sessions = [_session(session_id="s1"), _session(session_id="s2")]
        score = calculate_posture(sessions, [])
        assert score.total_sessions == 2

    def test_total_events_count(self) -> None:
        e1 = _event("s1")
        e2 = _event("s1")
        session = Session("s1", events=[e1, e2])
        score = calculate_posture([session], [])
        assert score.total_events == 2

    def test_total_alerts_count(self) -> None:
        alerts = [_alert(Severity.HIGH), _alert(Severity.CRITICAL)]
        score = calculate_posture([_session()], alerts)
        assert score.total_alerts == 2

    def test_alerts_by_severity(self) -> None:
        alerts = [
            _alert(Severity.CRITICAL),
            _alert(Severity.CRITICAL),
            _alert(Severity.HIGH),
        ]
        score = calculate_posture([_session()], alerts)
        assert score.alerts_by_severity[Severity.CRITICAL] == 2
        assert score.alerts_by_severity[Severity.HIGH] == 1
        assert score.alerts_by_severity[Severity.MEDIUM] == 0
        assert score.alerts_by_severity[Severity.LOW] == 0

    def test_elevated_event_ratio(self) -> None:
        normal = Event(
            session_id="s1",
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            action_type=ActionType.SHELL_EXEC,
            target=Target(tool_name="Bash", command="pytest"),
            elevated=False,
        )
        elevated = Event(
            session_id="s1",
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            action_type=ActionType.SHELL_EXEC,
            target=Target(tool_name="Bash", command="sudo ..."),
            elevated=True,
        )
        session = Session("s1", events=[normal, elevated])
        score = calculate_posture([session], [])
        assert score.elevated_event_ratio == pytest.approx(0.5)

    def test_elevated_ratio_zero_events(self) -> None:
        score = calculate_posture([Session("s1")], [])
        assert score.elevated_event_ratio == 0.0


class TestGrades:
    @pytest.mark.parametrize(
        "score_val,expected_grade",
        [
            (100, "A"),
            (90, "A"),
            (89, "B"),
            (75, "B"),
            (74, "C"),
            (60, "C"),
            (59, "D"),
            (45, "D"),
            (44, "F"),
            (0, "F"),
        ],
    )
    def test_grade_boundaries(self, score_val: int, expected_grade: str) -> None:
        # Build an alert count that produces the desired score by testing grade directly
        from agent_spm.engine.posture import _grade

        assert _grade(score_val) == expected_grade
