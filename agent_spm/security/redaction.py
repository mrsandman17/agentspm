"""Redaction utilities for safely displaying command/path targets."""

from __future__ import annotations

import re

from agent_spm.domain.models import Target

_SENSITIVE_PATH_PATTERN = re.compile(
    r"(?i)(?:\.env(?:\.|$)|\.pem$|\.key$|\.p12$|\.pfx$|id_(?:rsa|dsa|ed25519)$|"
    r"credentials|secrets?[/\\]|/etc/(?:passwd|shadow|sudoers)|"
    r"(?:^|[/\\])\.gnupg(?:[/\\]|$)|(?:^|[/\\])\.kube[/\\]config$)"
)

_COMMAND_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(https?://[^/\s:@]+:)[^@\s/]+@", re.IGNORECASE),
        r"\1[REDACTED]@",
    ),
    (
        re.compile(
            r"(?i)(--?(?:password|passwd|token|secret|api[-_]?key|access[-_]?key|auth(?:orization)?)\s+)"
            r"(\"[^\"]*\"|'[^']*'|\S+)"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b((?:password|passwd|token|secret|api[_-]?key|access[_-]?key|auth(?:orization)?)\s*=\s*)"
            r"(\"[^\"]*\"|'[^']*'|[^\s]+(?:\s+[^\s]+)?)"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"\b([A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASS|API_KEY|ACCESS_KEY|AUTH)[A-Z0-9_]*)="
            r"(\"[^\"]*\"|'[^']*'|\S+)"
        ),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._-]+"),
        r"\1[REDACTED]",
    ),
]


def redact_command(command: str) -> str:
    """Mask common secret-bearing command tokens."""
    redacted = command
    for pattern, replacement in _COMMAND_REDACTIONS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_path(path: str) -> str:
    """Mask sensitive paths while keeping non-sensitive paths readable."""
    if _SENSITIVE_PATH_PATTERN.search(path):
        return "[REDACTED_PATH]"
    return path


def safe_target_text(target: Target) -> str:
    """Return a redacted display string for command/path/tool targets."""
    if target.command:
        return redact_command(target.command)
    if target.path:
        return redact_path(target.path)
    return target.tool_name
