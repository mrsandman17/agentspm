"""Tests for posture CLI behavior."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from agent_spm.cli.posture import posture


def test_posture_loads_all_policies_by_default() -> None:
    runner = CliRunner()
    with (
        patch("agent_spm.cli.posture.load_all_policies", return_value=[]) as mocked_loader,
        patch("agent_spm.cli.posture.scan_sessions", return_value=[]),
    ):
        result = runner.invoke(posture, [])
        assert result.exit_code == 0
        mocked_loader.assert_called_once_with(user_policy_path=None)
