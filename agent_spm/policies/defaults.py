"""Built-in default security policy.

Covers the most common high-risk agent behaviors without requiring any
user configuration. Users can extend or override with custom YAML policies.
"""

from __future__ import annotations

from agent_spm.domain.models import ActionType, Policy, PolicyRule, RuleMatch, Severity

DEFAULT_POLICY = Policy(
    name="default",
    description="Built-in policy for common agent security risks",
    rules=[
        PolicyRule(
            name="elevated-shell-command",
            description=("Shell command flagged as elevated (sudo, chmod 777, chown)"),
            severity=Severity.MEDIUM,
            match=RuleMatch(
                action_types=[ActionType.SHELL_EXEC],
                elevated=True,
            ),
        ),
        PolicyRule(
            name="sensitive-file-access",
            description=(
                "Read or write of sensitive files (.env, .pem, .key, "
                "credentials, secrets/, /etc/passwd)"
            ),
            severity=Severity.HIGH,
            match=RuleMatch(
                action_types=[ActionType.FILE_READ, ActionType.FILE_WRITE],
                elevated=True,
            ),
        ),
        PolicyRule(
            name="force-push",
            description="Force push to git remote — can permanently destroy history",
            severity=Severity.CRITICAL,
            match=RuleMatch(
                action_types=[ActionType.SHELL_EXEC],
                command_pattern=r"git push .*(--force|-f\b)",
            ),
        ),
        PolicyRule(
            name="curl-pipe-bash",
            description="Download and execute arbitrary code via curl|bash or wget|bash",
            severity=Severity.CRITICAL,
            match=RuleMatch(
                action_types=[ActionType.SHELL_EXEC],
                command_pattern=r"\b(curl|wget)\b.*\|\s*bash\b",
            ),
        ),
        PolicyRule(
            name="destructive-remove",
            description="Recursive force remove (rm -rf) — risk of permanent data loss",
            severity=Severity.MEDIUM,
            match=RuleMatch(
                action_types=[ActionType.SHELL_EXEC],
                command_pattern=r"\brm\s+-rf\b",
            ),
        ),
        PolicyRule(
            name="out-of-directory-access",
            description="Agent accessed files outside its working directory",
            severity=Severity.LOW,
            match=RuleMatch(
                action_types=[ActionType.FILE_READ, ActionType.FILE_WRITE],
                out_of_directory=True,
            ),
        ),
    ],
)


def get_default_rule(name: str) -> PolicyRule | None:
    """Return the default PolicyRule with the given name, or None if not found."""
    for rule in DEFAULT_POLICY.rules:
        if rule.name == name:
            return rule
    return None
