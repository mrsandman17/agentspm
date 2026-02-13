"""Tests for agent_spm/policies/writer.py."""

from __future__ import annotations

from pathlib import Path

import yaml

from agent_spm.domain.models import ActionType, PolicyRule, RuleMatch, Severity
from agent_spm.policies.loader import load_policy
from agent_spm.policies.writer import (
    _rule_to_dict,
    clear_custom_rules,
    list_custom_rules,
    remove_custom_rule,
    save_custom_rule,
    set_rule_enabled,
)


def _rule(
    name: str = "test-rule",
    severity: Severity = Severity.HIGH,
    command_pattern: str | None = "rm -rf",
    action_types: list[ActionType] | None = None,
    enabled: bool = True,
) -> PolicyRule:
    if action_types is None:
        action_types = [ActionType.SHELL_EXEC]
    return PolicyRule(
        name=name,
        description=f"Test rule {name}",
        severity=severity,
        match=RuleMatch(action_types=action_types, command_pattern=command_pattern),
        enabled=enabled,
    )


class TestRuleToDict:
    def test_basic_fields(self) -> None:
        rule = _rule(name="my-rule", severity=Severity.CRITICAL)
        d = _rule_to_dict(rule)
        assert d["name"] == "my-rule"
        assert d["severity"] == "critical"
        assert d["enabled"] is True

    def test_action_types_serialized(self) -> None:
        rule = _rule(action_types=[ActionType.FILE_READ, ActionType.FILE_WRITE])
        d = _rule_to_dict(rule)
        assert d["match"]["action_types"] == ["file_read", "file_write"]

    def test_none_action_types_omitted(self) -> None:
        rule = PolicyRule(
            name="any-action",
            description="",
            severity=Severity.LOW,
            match=RuleMatch(),
        )
        d = _rule_to_dict(rule)
        assert "action_types" not in d["match"]

    def test_disabled_rule(self) -> None:
        rule = _rule(enabled=False)
        d = _rule_to_dict(rule)
        assert d["enabled"] is False

    def test_out_of_directory_serialized(self) -> None:
        rule = PolicyRule(
            name="ood",
            description="",
            severity=Severity.MEDIUM,
            match=RuleMatch(out_of_directory=True),
        )
        d = _rule_to_dict(rule)
        assert d["match"]["out_of_directory"] is True


class TestRoundtrip:
    def test_roundtrip_via_load_policy(self, tmp_path: Path) -> None:
        rule = _rule(name="roundtrip-rule", severity=Severity.HIGH)
        path = tmp_path / "custom.yml"
        save_custom_rule(rule, path=path)

        loaded = load_policy(path)
        assert len(loaded.rules) == 1
        loaded_rule = loaded.rules[0]
        assert loaded_rule.name == "roundtrip-rule"
        assert loaded_rule.severity == Severity.HIGH
        assert loaded_rule.match.command_pattern == "rm -rf"
        assert loaded_rule.enabled is True


class TestSaveCustomRule:
    def test_creates_new_file(self, tmp_path: Path) -> None:
        path = tmp_path / "custom.yml"
        rule = _rule()
        save_custom_rule(rule, path=path)
        assert path.exists()
        data = yaml.safe_load(path.read_text())
        assert data["name"] == "custom"
        assert len(data["rules"]) == 1

    def test_appends_to_existing_file(self, tmp_path: Path) -> None:
        path = tmp_path / "custom.yml"
        save_custom_rule(_rule(name="rule-a"), path=path)
        save_custom_rule(_rule(name="rule-b"), path=path)
        data = yaml.safe_load(path.read_text())
        names = [r["name"] for r in data["rules"]]
        assert "rule-a" in names
        assert "rule-b" in names
        assert len(data["rules"]) == 2

    def test_overwrites_same_name(self, tmp_path: Path) -> None:
        path = tmp_path / "custom.yml"
        save_custom_rule(_rule(name="rule-a", severity=Severity.LOW), path=path)
        save_custom_rule(_rule(name="rule-a", severity=Severity.CRITICAL), path=path)
        data = yaml.safe_load(path.read_text())
        assert len(data["rules"]) == 1
        assert data["rules"][0]["severity"] == "critical"

    def test_returns_path(self, tmp_path: Path) -> None:
        path = tmp_path / "custom.yml"
        result = save_custom_rule(_rule(), path=path)
        assert result == path


class TestRemoveCustomRule:
    def test_removes_existing_rule(self, tmp_path: Path) -> None:
        path = tmp_path / "custom.yml"
        save_custom_rule(_rule(name="to-remove"), path=path)
        assert remove_custom_rule("to-remove", path=path) is True
        data = yaml.safe_load(path.read_text())
        assert all(r["name"] != "to-remove" for r in data["rules"])

    def test_returns_false_if_not_found(self, tmp_path: Path) -> None:
        path = tmp_path / "custom.yml"
        save_custom_rule(_rule(name="existing"), path=path)
        assert remove_custom_rule("nonexistent", path=path) is False

    def test_returns_false_if_no_file(self, tmp_path: Path) -> None:
        path = tmp_path / "nonexistent.yml"
        assert remove_custom_rule("anything", path=path) is False


class TestClearCustomRules:
    def test_deletes_file(self, tmp_path: Path) -> None:
        path = tmp_path / "custom.yml"
        save_custom_rule(_rule(), path=path)
        clear_custom_rules(path=path)
        assert not path.exists()

    def test_no_error_if_no_file(self, tmp_path: Path) -> None:
        path = tmp_path / "nonexistent.yml"
        clear_custom_rules(path=path)  # should not raise


class TestSetRuleEnabled:
    def test_disables_rule(self, tmp_path: Path) -> None:
        path = tmp_path / "custom.yml"
        save_custom_rule(_rule(name="target", enabled=True), path=path)
        assert set_rule_enabled("target", enabled=False, path=path) is True
        rules = list_custom_rules(path=path)
        assert rules[0]["enabled"] is False

    def test_enables_rule(self, tmp_path: Path) -> None:
        path = tmp_path / "custom.yml"
        save_custom_rule(_rule(name="target", enabled=False), path=path)
        assert set_rule_enabled("target", enabled=True, path=path) is True
        rules = list_custom_rules(path=path)
        assert rules[0]["enabled"] is True

    def test_returns_false_if_not_found(self, tmp_path: Path) -> None:
        path = tmp_path / "custom.yml"
        save_custom_rule(_rule(name="other"), path=path)
        assert set_rule_enabled("nonexistent", enabled=False, path=path) is False

    def test_returns_false_if_no_file(self, tmp_path: Path) -> None:
        path = tmp_path / "nonexistent.yml"
        assert set_rule_enabled("anything", enabled=False, path=path) is False


class TestListCustomRules:
    def test_returns_empty_if_no_file(self, tmp_path: Path) -> None:
        path = tmp_path / "nonexistent.yml"
        assert list_custom_rules(path=path) == []

    def test_returns_rules_with_enabled(self, tmp_path: Path) -> None:
        path = tmp_path / "custom.yml"
        save_custom_rule(_rule(name="r1", enabled=True), path=path)
        save_custom_rule(_rule(name="r2", enabled=False), path=path)
        rules = list_custom_rules(path=path)
        assert len(rules) == 2
        by_name = {r["name"]: r for r in rules}
        assert by_name["r1"]["enabled"] is True
        assert by_name["r2"]["enabled"] is False


class TestGeneratedYamlLoadable:
    def test_yaml_loadable_by_load_policy(self, tmp_path: Path) -> None:
        path = tmp_path / "custom.yml"
        save_custom_rule(
            PolicyRule(
                name="complex-rule",
                description="A rule with everything",
                severity=Severity.CRITICAL,
                match=RuleMatch(
                    action_types=[ActionType.SHELL_EXEC],
                    elevated=True,
                    command_pattern=r"deploy.*prod",
                    path_pattern=r"\.env$",
                ),
                enabled=True,
            ),
            path=path,
        )
        policy = load_policy(path)
        rule = policy.rules[0]
        assert rule.name == "complex-rule"
        assert rule.severity == Severity.CRITICAL
        assert rule.match.elevated is True
        assert rule.match.command_pattern == r"deploy.*prod"
        assert rule.match.path_pattern == r"\.env$"
