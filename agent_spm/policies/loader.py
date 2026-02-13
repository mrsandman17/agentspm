"""YAML policy loader.

Loads Policy objects from YAML files. The YAML schema mirrors the domain
models — no mapping magic needed.

Schema:
  name: string (required)
  description: string (optional)
  rules:
    - name: string
      description: string
      severity: low | medium | high | critical
      enabled: true | false  (optional, defaults to true)
      match:
        action_types: [tool_call | file_read | file_write | shell_exec]
        elevated: true | false
        command_pattern: regex string
        path_pattern: regex string
        out_of_directory: true | false
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from agent_spm.domain.models import ActionType, Policy, PolicyRule, RuleMatch, Severity

CUSTOM_POLICY_DIR = Path.home() / ".claude" / "agent_spm" / "policies"


def load_policy(path: Path) -> Policy:
    """Load a Policy from a YAML file.

    Raises:
        FileNotFoundError: if the file doesn't exist.
        ValueError: if the YAML is structurally invalid.
    """
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    with open(path) as f:
        data = yaml.safe_load(f) or {}

    return _parse_policy(data, source=str(path))


def load_policy_dir(directory: Path) -> list[Policy]:
    """Load all .yml/.yaml policy files from a directory.

    Returns an empty list if the directory doesn't exist or has no YAML files.
    """
    if not directory.exists():
        return []

    policies = []
    for path in sorted(directory.glob("*.y*ml")):
        if path.suffix in {".yml", ".yaml"}:
            policies.append(load_policy(path))
    return policies


def load_all_policies(user_policy_path: Path | None = None) -> list[Policy]:
    """Load default policy + custom rules + optional user-specified policy.

    Load order:
    1. Built-in DEFAULT_POLICY
    2. Custom rules from CUSTOM_POLICY_DIR (if any)
    3. user_policy_path (if provided)

    Custom rules with the same name as a default rule override the default
    (the default version is removed and the custom version takes effect).
    This allows users to disable or modify built-in rules.
    """
    from agent_spm.policies.defaults import DEFAULT_POLICY

    policies: list[Policy] = [DEFAULT_POLICY]

    custom_policies = load_policy_dir(CUSTOM_POLICY_DIR)
    policies.extend(custom_policies)

    if user_policy_path is not None:
        if user_policy_path.is_dir():
            loaded = load_policy_dir(user_policy_path)
            policies.extend(loaded if loaded else [])
        else:
            policies.append(load_policy(user_policy_path))

    return _apply_overrides(policies)


def _apply_overrides(policies: list[Policy]) -> list[Policy]:
    """Remove default rules that are overridden by same-named custom rules.

    When a custom rule shares a name with a default rule, the custom version
    takes precedence. The default rule is removed from the first (default)
    policy to prevent double-firing.
    """
    if len(policies) <= 1:
        return policies

    # Collect names of all rules in non-default policies
    override_names: set[str] = set()
    for policy in policies[1:]:
        for rule in policy.rules:
            override_names.add(rule.name)

    if not override_names:
        return policies

    default = policies[0]
    filtered_rules = [r for r in default.rules if r.name not in override_names]
    filtered_default = Policy(
        name=default.name,
        description=default.description,
        rules=filtered_rules,
    )
    return [filtered_default, *policies[1:]]


def _parse_policy(data: dict[str, Any], source: str = "") -> Policy:
    name = data.get("name")
    if not name:
        raise ValueError(f"Policy missing 'name' field (source: {source})")

    rules = [_parse_rule(r, source=source) for r in (data.get("rules") or [])]

    return Policy(
        name=name,
        description=data.get("description", ""),
        rules=rules,
    )


def _parse_rule(data: dict[str, Any], source: str = "") -> PolicyRule:
    name = data.get("name")
    if not name:
        raise ValueError(f"Rule missing 'name' field (source: {source})")

    severity_str = data.get("severity", "medium")
    try:
        severity = Severity(severity_str)
    except ValueError as err:
        raise ValueError(f"Invalid severity '{severity_str}' in rule '{name}'") from err

    match_data = data.get("match") or {}
    match = _parse_match(match_data, rule_name=name)

    enabled = data.get("enabled", True)

    return PolicyRule(
        name=name,
        description=data.get("description", ""),
        severity=severity,
        match=match,
        enabled=bool(enabled),
    )


def _parse_match(data: dict[str, Any], rule_name: str = "") -> RuleMatch:
    action_types = None
    if "action_types" in data:
        raw = data["action_types"]
        action_types = []
        for at in raw:
            try:
                action_types.append(ActionType(at))
            except ValueError as err:
                raise ValueError(f"Invalid action_type '{at}' in rule '{rule_name}'") from err

    elevated = data.get("elevated")  # None if not specified
    out_of_directory = data.get("out_of_directory")  # None if not specified

    return RuleMatch(
        action_types=action_types,
        elevated=elevated,
        command_pattern=data.get("command_pattern"),
        path_pattern=data.get("path_pattern"),
        out_of_directory=out_of_directory,
    )
