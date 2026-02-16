"""Custom policy writer — persist user-defined rules to ~/.claude/agent_spm/policies/custom.yml.

Rules are stored in a flat YAML list. Each rule has an `enabled` field that
can be toggled without deleting the rule.
"""

from __future__ import annotations

import os
from contextlib import suppress
from pathlib import Path
from typing import Any

import yaml

from agent_spm.domain.models import PolicyRule

CUSTOM_POLICY_PATH = Path.home() / ".claude" / "agent_spm" / "policies" / "custom.yml"


def save_custom_rule(rule: PolicyRule, path: Path = CUSTOM_POLICY_PATH) -> Path:
    """Append a rule to the custom policy file. Creates the file if needed."""
    data = _load_custom_yaml(path) or _empty_policy()
    rules: list[dict[str, Any]] = data.setdefault("rules", [])

    # Replace existing rule with same name, or append
    for i, r in enumerate(rules):
        if r.get("name") == rule.name:
            rules[i] = _rule_to_dict(rule)
            break
    else:
        rules.append(_rule_to_dict(rule))

    _save_custom_yaml(data, path)
    return path


def remove_custom_rule(name: str, path: Path = CUSTOM_POLICY_PATH) -> bool:
    """Remove a rule by name. Returns True if found and removed."""
    data = _load_custom_yaml(path)
    if not data:
        return False

    rules: list[dict[str, Any]] = data.get("rules", [])
    before = len(rules)
    data["rules"] = [r for r in rules if r.get("name") != name]

    if len(data["rules"]) == before:
        return False

    _save_custom_yaml(data, path)
    return True


def clear_custom_rules(path: Path = CUSTOM_POLICY_PATH) -> None:
    """Delete the custom policy file, removing all custom rules."""
    if path.exists():
        path.unlink()


def set_rule_enabled(name: str, enabled: bool, path: Path = CUSTOM_POLICY_PATH) -> bool:
    """Toggle enabled/disabled on a rule by name. Returns True if found.

    For ``enabled=False``: also searches built-in default rules and clones
    the rule to custom.yml with ``enabled: false`` if found there.
    For ``enabled=True``: updates the custom override if present; returns
    True without writing if the rule is a built-in default (already enabled).
    """
    # Check custom.yml first
    data = _load_custom_yaml(path)
    if data:
        for rule in data.get("rules", []):
            if rule.get("name") == name:
                rule["enabled"] = enabled
                _save_custom_yaml(data, path)
                return True

    # Not in custom.yml — check default rules
    from agent_spm.policies.defaults import get_default_rule

    default_rule = get_default_rule(name)
    if default_rule is None:
        return False

    if not enabled:
        # Clone the default rule to custom.yml with enabled=False
        from dataclasses import replace as _replace

        disabled_rule = _replace(default_rule, enabled=False)
        save_custom_rule(disabled_rule, path=path)
        return True
    else:
        # Default rule exists and is already enabled — no action needed
        return True


def list_custom_rules(path: Path = CUSTOM_POLICY_PATH) -> list[dict[str, Any]]:
    """Return raw rule dicts (with enabled field) from the custom file."""
    data = _load_custom_yaml(path)
    if not data:
        return []
    return list(data.get("rules", []))


def _rule_to_dict(rule: PolicyRule) -> dict[str, Any]:
    d: dict[str, Any] = {
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity.value,
        "enabled": rule.enabled,
        "match": {},
    }
    m = rule.match
    if m.action_types is not None:
        d["match"]["action_types"] = [at.value for at in m.action_types]
    if m.elevated is not None:
        d["match"]["elevated"] = m.elevated
    if m.command_pattern is not None:
        d["match"]["command_pattern"] = m.command_pattern
    if m.path_pattern is not None:
        d["match"]["path_pattern"] = m.path_pattern
    if m.out_of_directory is not None:
        d["match"]["out_of_directory"] = m.out_of_directory
    return d


def _empty_policy() -> dict[str, Any]:
    return {
        "name": "custom",
        "description": "User-defined custom rules",
        "rules": [],
    }


def _load_custom_yaml(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or None


def _save_custom_yaml(data: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    with suppress(OSError):
        os.chmod(path, 0o600)
