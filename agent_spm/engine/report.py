"""Report generation engine.

Produces a Markdown security posture report from sessions, alerts, and policies.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from agent_spm.domain.models import Alert, Event, Policy, PostureScore, Session
from agent_spm.engine.posture import calculate_posture
from agent_spm.security.redaction import safe_target_text


@dataclass(frozen=True)
class Report:
    """Structured security posture report for a set of agent sessions."""

    generated_at: datetime
    posture: PostureScore
    policy_names: list[str]
    top_alerts: list[Alert]
    elevated_events: list[Event]


def generate_report(
    sessions: list[Session],
    alerts: list[Alert],
    policies: list[Policy],
    top_n: int = 10,
) -> Report:
    """Build a Report from scanned sessions, evaluated alerts, and active policies."""
    posture = calculate_posture(sessions, alerts)

    sorted_alerts = sorted(alerts, key=lambda a: a.severity, reverse=True)

    all_elevated = [e for s in sessions for e in s.elevated_events]

    return Report(
        generated_at=datetime.now(UTC),
        posture=posture,
        policy_names=[p.name for p in policies],
        top_alerts=sorted_alerts[:top_n],
        elevated_events=all_elevated[:top_n],
    )


def generate_markdown_report(
    sessions: list[Session],
    alerts: list[Alert],
    policies: list[Policy],
) -> str:
    """Generate a Markdown report directly from sessions, alerts, and policies."""
    report = generate_report(sessions, alerts, policies)
    return render_markdown(report)


def render_markdown(report: Report) -> str:
    """Render a Report as a Markdown string."""
    lines: list[str] = []
    ps = report.posture

    lines.append("# Agent Security Posture Report")
    lines.append("")
    lines.append(f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"Policies: {', '.join(report.policy_names)}")
    lines.append("")

    # Score summary
    lines.append("## Posture Score")
    lines.append("")
    lines.append(f"**{ps.score}/100** — Grade: **{ps.grade}**")
    lines.append("")
    lines.append(
        f"Sessions: {ps.total_sessions} | "
        f"Events: {ps.total_events} | "
        f"Alerts: {ps.total_alerts} | "
        f"Elevated: {ps.elevated_event_ratio:.0%}"
    )
    lines.append("")

    # Alert breakdown
    lines.append("## Alert Breakdown")
    lines.append("")
    lines.append("| Severity | Alerts |")
    lines.append("|---|---|")
    for sev_name in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        from agent_spm.domain.models import Severity

        sev = Severity(sev_name.lower())
        count = ps.alerts_by_severity.get(sev, 0)
        lines.append(f"| {sev_name} | {count} |")
    lines.append("")

    # Top policy violations
    lines.append("## Top Policy Violations")
    lines.append("")
    if not report.top_alerts:
        lines.append("No policy violations detected.")
    else:
        lines.append("| Severity | Rule | Target |")
        lines.append("|---|---|---|")
        for alert in report.top_alerts:
            target = safe_target_text(alert.event.target)
            lines.append(f"| {alert.severity.value.upper()} | {alert.rule_name} | `{target}` |")
    lines.append("")

    # Elevated events (only if any)
    if report.elevated_events:
        lines.append("## Elevated Events")
        lines.append("")
        lines.append("| Session | Time | Tool | Command/Path |")
        lines.append("|---|---|---|---|")
        for event in report.elevated_events:
            target = safe_target_text(event.target)
            ts = event.timestamp.strftime("%Y-%m-%d %H:%M")
            lines.append(f"| {event.session_id} | {ts} | {event.target.tool_name} | `{target}` |")
        lines.append("")

    return "\n".join(lines)
