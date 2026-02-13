"""Policy evaluator — check sessions against policies and generate alerts.

Maps to SSPM "policy evaluation" — comparing what the agent did against
what it should have done, surfacing violations as Alerts.
"""

from __future__ import annotations

from agent_spm.domain.models import Alert, Event, Policy, PolicyRule, Session


def evaluate(sessions: list[Session], policies: list[Policy]) -> list[Alert]:
    """Evaluate sessions against policies and return all triggered alerts.

    Args:
        sessions: Parsed agent sessions with events.
        policies: Policies to evaluate against.

    Returns:
        List of Alerts, one per (event, rule) pair that matched.
        Ordered by session then event timestamp.
    """
    alerts: list[Alert] = []
    for session in sessions:
        for event in session.events:
            for policy in policies:
                for rule in policy.rules:
                    if rule.enabled and rule.match.matches(event, session=session):
                        alerts.append(_make_alert(rule, event))
    return alerts


def _make_alert(rule: PolicyRule, event: Event) -> Alert:
    target = event.target.command or event.target.path or event.target.tool_name
    message = f"[{rule.name}] {rule.description} — {target}"
    return Alert(
        rule_name=rule.name,
        severity=rule.severity,
        event=event,
        message=message,
    )
