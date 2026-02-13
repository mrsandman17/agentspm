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
      match:
        action_types: [tool_call | file_read | file_write | shell_exec]
        elevated: true | false
        command_pattern: regex string
        path_pattern: regex string
"""

from __future__ import annotations

from pathlib import Path

import yaml

from agent_spm.domain.models import ActionType, Policy, PolicyRule, RuleMatch, Severity


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


def _parse_policy(data: dict, source: str = "") -> Policy:
    name = data.get("name")
    if not name:
        raise ValueError(f"Policy missing 'name' field (source: {source})")

    rules = [_parse_rule(r, source=source) for r in (data.get("rules") or [])]

    return Policy(
        name=name,
        description=data.get("description", ""),
        rules=rules,
    )


def _parse_rule(data: dict, source: str = "") -> PolicyRule:
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

    return PolicyRule(
        name=name,
        description=data.get("description", ""),
        severity=severity,
        match=match,
    )


def _parse_match(data: dict, rule_name: str = "") -> RuleMatch:
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

    return RuleMatch(
        action_types=action_types,
        elevated=elevated,
        command_pattern=data.get("command_pattern"),
        path_pattern=data.get("path_pattern"),
    )
