"""Tests for redaction helpers."""

from __future__ import annotations

from agent_spm.domain.models import Target
from agent_spm.security.redaction import redact_command, redact_path, safe_target_text


def test_redact_command_flag_value() -> None:
    cmd = "deploy --token abc123 --env prod"
    out = redact_command(cmd)
    assert "--token [REDACTED]" in out
    assert "abc123" not in out


def test_redact_command_url_credentials() -> None:
    cmd = "curl https://user:password@example.com/install.sh"
    out = redact_command(cmd)
    assert "password" not in out
    assert "[REDACTED]" in out


def test_redact_sensitive_path() -> None:
    assert redact_path("/home/user/.ssh/id_rsa") == "[REDACTED_PATH]"


def test_safe_target_text_prefers_command_redaction() -> None:
    target = Target(tool_name="Bash", command="echo API_KEY=supersecret")
    out = safe_target_text(target)
    assert "supersecret" not in out
    assert "[REDACTED]" in out
