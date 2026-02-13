"""Posture scoring engine.

Calculates a 0–100 security posture score from sessions and alerts.
Deductions are capped per severity band to prevent a single category
from dominating the score.

Deduction schedule:
  CRITICAL — 20 pts each, max 40
  HIGH     — 10 pts each, max 30
  MEDIUM   —  3 pts each, max 15
  LOW      —  1 pt  each, max  5
"""

from __future__ import annotations

from agent_spm.domain.models import Alert, PostureScore, Session, Severity

_DEDUCTIONS: dict[Severity, tuple[int, int]] = {
    Severity.CRITICAL: (20, 40),
    Severity.HIGH: (10, 30),
    Severity.MEDIUM: (3, 15),
    Severity.LOW: (1, 5),
}


def calculate_posture(sessions: list[Session], alerts: list[Alert]) -> PostureScore:
    """Compute a PostureScore from scanned sessions and evaluated alerts."""
    total_events = sum(s.total_events for s in sessions)
    elevated_events = sum(len(s.elevated_events) for s in sessions)
    elevated_ratio = elevated_events / total_events if total_events else 0.0

    counts: dict[Severity, int] = {sev: 0 for sev in Severity}
    for alert in alerts:
        counts[alert.severity] += 1

    deduction = 0
    for sev, (per_alert, cap) in _DEDUCTIONS.items():
        deduction += min(counts[sev] * per_alert, cap)

    score = max(0, 100 - deduction)

    return PostureScore(
        score=score,
        grade=_grade(score),
        total_sessions=len(sessions),
        total_events=total_events,
        total_alerts=len(alerts),
        alerts_by_severity=dict(counts),
        elevated_event_ratio=elevated_ratio,
    )


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 45:
        return "D"
    return "F"
