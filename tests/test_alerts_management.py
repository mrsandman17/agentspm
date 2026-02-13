"""Tests for the refactored alerts CLI group and rule management subcommands."""

from __future__ import annotations

from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from agent_spm.cli.alerts import alerts
from agent_spm.domain.models import (
    ActionType,
    Event,
    PolicyRule,
    RuleMatch,
    Session,
    Severity,
    Target,
)
from agent_spm.policies.writer import (
    clear_custom_rules,
    list_custom_rules,
    remove_custom_rule,
    save_custom_rule,
    set_rule_enabled,
)


def _dt(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)


def _session(session_id: str = "abc123def456") -> Session:
    event = Event(
        session_id=session_id,
        timestamp=_dt(2024, 1, 1, 12, 0, 0),
        action_type=ActionType.SHELL_EXEC,
        target=Target(tool_name="Bash", command="sudo rm -rf /"),
        elevated=True,
    )
    return Session(
        session_id=session_id,
        model="claude-sonnet",
        cwd="/home/user/project",
        started_at=_dt(2024, 1, 1, 12, 0, 0),
        events=[event],
    )


def _rule(name: str = "test-rule", severity: Severity = Severity.HIGH) -> PolicyRule:
    return PolicyRule(
        name=name,
        description=f"Test rule {name}",
        severity=severity,
        match=RuleMatch(action_types=[ActionType.SHELL_EXEC], elevated=True),
        enabled=True,
    )


class TestAlertsDefaultBehavior:
    """alerts (no subcommand) shows aggregated summary by default."""

    def test_lists_violations(self) -> None:
        runner = CliRunner()
        with patch("agent_spm.cli.alerts.scan_sessions", return_value=[_session()]):
            result = runner.invoke(alerts, [])
        assert result.exit_code == 0
        assert "Alerts" in result.output

    def test_aggregated_by_default(self) -> None:
        runner = CliRunner()
        with patch("agent_spm.cli.alerts.scan_sessions", return_value=[_session()]):
            result = runner.invoke(alerts, [])
        assert result.exit_code == 0
        # Aggregated view shows rule names and counts, not individual session IDs
        assert "Count" in result.output or "--detail" in result.output

    def test_detail_flag_shows_individual_violations(self) -> None:
        runner = CliRunner()
        with patch("agent_spm.cli.alerts.scan_sessions", return_value=[_session()]):
            result = runner.invoke(alerts, ["--detail"])
        assert result.exit_code == 0
        assert "Alerts" in result.output

    def test_empty_sessions(self) -> None:
        runner = CliRunner()
        with patch("agent_spm.cli.alerts.scan_sessions", return_value=[]):
            result = runner.invoke(alerts, [])
        assert result.exit_code == 0
        assert "No sessions found" in result.output


class TestAlertsRules:
    """alerts rules — shows all rules with source/status."""

    def test_shows_rules(self) -> None:
        runner = CliRunner()
        result = runner.invoke(alerts, ["rules"])
        assert result.exit_code == 0
        assert "elevated-shell-command" in result.output
        assert "out-of-directory-access" in result.output

    def test_shows_default_source(self) -> None:
        runner = CliRunner()
        result = runner.invoke(alerts, ["rules"])
        assert result.exit_code == 0
        assert "default" in result.output

    def test_shows_enabled_status(self) -> None:
        runner = CliRunner()
        result = runner.invoke(alerts, ["rules"])
        assert result.exit_code == 0
        assert "enabled" in result.output

    def test_shows_custom_rule_when_present(self, tmp_path: Path) -> None:
        custom_path = tmp_path / "custom.yml"
        save_custom_rule(_rule(name="my-custom-rule"), path=custom_path)

        runner = CliRunner()
        with (
            patch("agent_spm.policies.loader.CUSTOM_POLICY_DIR", tmp_path),
            patch(
                "agent_spm.cli.alerts.list_custom_rules",
                partial(list_custom_rules, path=custom_path),
            ),
        ):
            result = runner.invoke(alerts, ["rules"])
        assert result.exit_code == 0


class TestAlertsAdd:
    """alerts add — interactive wizard."""

    def test_add_rule_with_input(self, tmp_path: Path) -> None:
        custom_path = tmp_path / "custom.yml"
        runner = CliRunner()

        user_input = (
            "\n".join(
                [
                    "my-rule",  # name
                    "Test rule",  # description
                    "high",  # severity
                    "shell_exec",  # action types
                    "any",  # elevated
                    "deploy.*prod",  # command pattern
                    "",  # path pattern (empty)
                    "y",  # confirm save
                ]
            )
            + "\n"
        )

        with patch(
            "agent_spm.cli.alerts.save_custom_rule", partial(save_custom_rule, path=custom_path)
        ):
            result = runner.invoke(alerts, ["add"], input=user_input)

        assert result.exit_code == 0
        assert "saved" in result.output.lower() or "my-rule" in result.output

    def test_add_cancelled(self, tmp_path: Path) -> None:
        custom_path = tmp_path / "custom.yml"
        runner = CliRunner()

        user_input = (
            "\n".join(
                [
                    "my-rule",
                    "Test rule",
                    "high",
                    "all",
                    "any",
                    "",
                    "",
                    "n",  # cancel
                ]
            )
            + "\n"
        )

        with patch(
            "agent_spm.cli.alerts.save_custom_rule", partial(save_custom_rule, path=custom_path)
        ):
            result = runner.invoke(alerts, ["add"], input=user_input)

        assert result.exit_code == 0
        assert "Cancelled" in result.output
        assert not custom_path.exists()

    def test_invalid_regex_rejected(self) -> None:
        runner = CliRunner()

        user_input = (
            "\n".join(
                [
                    "my-rule",
                    "Test rule",
                    "high",
                    "all",
                    "any",
                    "[invalid",  # bad regex for command pattern
                ]
            )
            + "\n"
        )

        result = runner.invoke(alerts, ["add"], input=user_input)
        assert result.exit_code != 0 or "Invalid regex" in result.output

    def test_invalid_name_rejected(self) -> None:
        runner = CliRunner()
        user_input = "INVALID NAME\n"
        result = runner.invoke(alerts, ["add"], input=user_input)
        # Should fail name validation
        assert result.exit_code != 0 or "Name must be" in result.output


class TestAlertsRemove:
    def test_removes_existing_rule(self, tmp_path: Path) -> None:
        custom_path = tmp_path / "custom.yml"
        save_custom_rule(_rule(name="to-remove"), path=custom_path)

        runner = CliRunner()
        with patch(
            "agent_spm.cli.alerts.remove_custom_rule", partial(remove_custom_rule, path=custom_path)
        ):
            result = runner.invoke(alerts, ["remove", "to-remove"])

        assert result.exit_code == 0
        assert "removed" in result.output.lower()

    def test_remove_nonexistent(self, tmp_path: Path) -> None:
        custom_path = tmp_path / "custom.yml"
        runner = CliRunner()
        with patch(
            "agent_spm.cli.alerts.remove_custom_rule", partial(remove_custom_rule, path=custom_path)
        ):
            result = runner.invoke(alerts, ["remove", "nonexistent"])
        assert result.exit_code != 0


class TestAlertsClear:
    def test_clears_all_rules(self, tmp_path: Path) -> None:
        custom_path = tmp_path / "custom.yml"
        save_custom_rule(_rule(name="r1"), path=custom_path)

        runner = CliRunner()
        with (
            patch("agent_spm.cli.alerts.CUSTOM_POLICY_PATH", custom_path),
            patch(
                "agent_spm.cli.alerts.clear_custom_rules",
                partial(clear_custom_rules, path=custom_path),
            ),
        ):
            result = runner.invoke(alerts, ["clear"], input="y\n")

        assert result.exit_code == 0
        assert not custom_path.exists()

    def test_clear_no_file(self, tmp_path: Path) -> None:
        custom_path = tmp_path / "nonexistent.yml"
        runner = CliRunner()
        with patch("agent_spm.cli.alerts.CUSTOM_POLICY_PATH", custom_path):
            result = runner.invoke(alerts, ["clear"])
        assert result.exit_code == 0
        assert "No custom rules" in result.output


class TestAlertsDefault:
    def test_resets_to_defaults(self, tmp_path: Path) -> None:
        custom_path = tmp_path / "custom.yml"
        custom_path.write_text("name: custom\nrules: []\n")

        runner = CliRunner()
        with patch("agent_spm.cli.alerts.CUSTOM_POLICY_PATH", custom_path):
            result = runner.invoke(alerts, ["default"], input="y\n")

        assert result.exit_code == 0
        assert not custom_path.exists()

    def test_default_no_file(self, tmp_path: Path) -> None:
        custom_path = tmp_path / "nonexistent.yml"
        runner = CliRunner()
        with patch("agent_spm.cli.alerts.CUSTOM_POLICY_PATH", custom_path):
            result = runner.invoke(alerts, ["default"])
        assert result.exit_code == 0
        assert "Already at defaults" in result.output


class TestAlertsEnableDisable:
    def test_disable_rule(self, tmp_path: Path) -> None:
        custom_path = tmp_path / "custom.yml"
        save_custom_rule(_rule(name="target"), path=custom_path)

        runner = CliRunner()
        with patch(
            "agent_spm.cli.alerts.set_rule_enabled", partial(set_rule_enabled, path=custom_path)
        ):
            result = runner.invoke(alerts, ["disable", "target"])

        assert result.exit_code == 0
        assert "disabled" in result.output.lower()

    def test_enable_rule(self, tmp_path: Path) -> None:
        custom_path = tmp_path / "custom.yml"
        save_custom_rule(
            PolicyRule(
                name="target",
                description="",
                severity=Severity.LOW,
                match=RuleMatch(),
                enabled=False,
            ),
            path=custom_path,
        )

        runner = CliRunner()
        with patch(
            "agent_spm.cli.alerts.set_rule_enabled", partial(set_rule_enabled, path=custom_path)
        ):
            result = runner.invoke(alerts, ["enable", "target"])

        assert result.exit_code == 0
        assert "enabled" in result.output.lower()

    def test_enable_nonexistent(self, tmp_path: Path) -> None:
        custom_path = tmp_path / "nonexistent.yml"
        runner = CliRunner()
        with patch(
            "agent_spm.cli.alerts.set_rule_enabled", partial(set_rule_enabled, path=custom_path)
        ):
            result = runner.invoke(alerts, ["enable", "nonexistent"])
        assert result.exit_code != 0


class TestDisableDefaultRules:
    """Disabling default rules creates a custom override."""

    def test_disable_default_rule_creates_override(self, tmp_path: Path) -> None:
        custom_path = tmp_path / "custom.yml"
        runner = CliRunner()
        with patch(
            "agent_spm.cli.alerts.set_rule_enabled", partial(set_rule_enabled, path=custom_path)
        ):
            result = runner.invoke(alerts, ["disable", "out-of-directory-access"])
        assert result.exit_code == 0
        assert "disabled" in result.output.lower()
        # Verify override was written to custom.yml
        rules = list_custom_rules(path=custom_path)
        assert any(r["name"] == "out-of-directory-access" and r["enabled"] is False for r in rules)

    def test_enable_default_rule_returns_success(self, tmp_path: Path) -> None:
        custom_path = tmp_path / "custom.yml"
        runner = CliRunner()
        with patch(
            "agent_spm.cli.alerts.set_rule_enabled", partial(set_rule_enabled, path=custom_path)
        ):
            result = runner.invoke(alerts, ["enable", "out-of-directory-access"])
        assert result.exit_code == 0
        assert "enabled" in result.output.lower()

    def test_disable_unknown_rule_fails(self, tmp_path: Path) -> None:
        custom_path = tmp_path / "custom.yml"
        runner = CliRunner()
        with patch(
            "agent_spm.cli.alerts.set_rule_enabled", partial(set_rule_enabled, path=custom_path)
        ):
            result = runner.invoke(alerts, ["disable", "nonexistent-rule-xyz"])
        assert result.exit_code != 0

    def test_load_all_policies_applies_override(self, tmp_path: Path) -> None:
        """Disabled default rule should not fire after override."""
        from agent_spm.policies.loader import load_all_policies
        from agent_spm.policies.writer import set_rule_enabled as _sre

        # Write override to a file inside tmp_path (which becomes CUSTOM_POLICY_DIR)
        custom_path = tmp_path / "custom.yml"
        _sre("out-of-directory-access", enabled=False, path=custom_path)

        with patch("agent_spm.policies.loader.CUSTOM_POLICY_DIR", tmp_path):
            policies = load_all_policies()

        # The default version should be gone; only the disabled override remains
        all_rules = [r for p in policies for r in p.rules]
        ood_rules = [r for r in all_rules if r.name == "out-of-directory-access"]
        assert len(ood_rules) == 1
        assert ood_rules[0].enabled is False


class TestAlertsTest:
    def test_dry_run_all_rules(self) -> None:
        runner = CliRunner()
        with patch("agent_spm.cli.alerts.scan_sessions", return_value=[_session()]):
            result = runner.invoke(alerts, ["test"])
        assert result.exit_code == 0
        assert "session" in result.output.lower()

    def test_dry_run_specific_rule(self) -> None:
        runner = CliRunner()
        with patch("agent_spm.cli.alerts.scan_sessions", return_value=[_session()]):
            result = runner.invoke(alerts, ["test", "--rule", "elevated-shell-command"])
        assert result.exit_code == 0

    def test_dry_run_nonexistent_rule(self) -> None:
        runner = CliRunner()
        with patch("agent_spm.cli.alerts.scan_sessions", return_value=[_session()]):
            result = runner.invoke(alerts, ["test", "--rule", "nonexistent-rule"])
        assert result.exit_code != 0

    def test_no_sessions(self) -> None:
        runner = CliRunner()
        with patch("agent_spm.cli.alerts.scan_sessions", return_value=[]):
            result = runner.invoke(alerts, ["test"])
        assert result.exit_code == 0
        assert "No sessions found" in result.output
