# agent-spm

**Agent Security Posture Manager** — SSPM applied to AI agents.

Observe what your AI agents did, evaluate against security policies, and surface risk. Think security camera, not security guard.

## The Problem

AI agents run with broad permissions and zero visibility. A Claude Code session might read sensitive config files, execute destructive shell commands, or force-push to protected branches — and you'd never know unless something broke. `agent-spm` closes that gap.

## How It Works

`agent-spm` applies [SSPM](https://www.gartner.com/en/information-technology/glossary/sspm) (SaaS Security Posture Management) concepts to AI agents:

| SSPM | agent-spm |
|---|---|
| Users | Agent sessions |
| SaaS Applications | Tools, MCPs, file systems |
| Permissions | Agent scopes (what they can do) |
| Security Policies | What agents *should* do |
| Posture Score | Drift between can and should |
| Misconfiguration Alert | Policy violation |

1. **Scan** — parse Claude Code JSONL session logs into normalized events
2. **Evaluate** — check every event against YAML security policies
3. **Score** — calculate a 0–100 posture score with letter grade
4. **Report** — surface violations, elevated events, and risk trends

## Quick Start

```bash
pip install agent-spm

# Scan your recent Claude Code sessions (reads ~/.claude/projects/)
agent-spm scan

# Security posture dashboard
agent-spm posture

# Browse what tools were used
agent-spm inventory

# Event timeline
agent-spm events --elevated   # show only elevated/risky events

# Policy violations
agent-spm alerts

# Generate a Markdown report
agent-spm report --output report.md
```

## Commands

### `agent-spm scan`
Parse Claude Code session logs from `~/.claude/projects/` into a local SQLite database.

```
Options:
  --path DIR     Override default ~/.claude/projects/ directory
  --limit N      Maximum number of sessions to scan
```

### `agent-spm posture`
Security posture dashboard — score, grade, and alert breakdown.

```
╭──────────────────────── Security Posture ──────────────────────────╮
│ 70/100  Grade: C                                                    │
│ Sessions: 5  Events: 84  Alerts: 12  Elevated: 23%  Policies: default │
╰─────────────────────────────────────────────────────────────────────╯
 Severity   Alerts  Deduction  Cap
 CRITICAL        1        -20   40
 HIGH            5        -10   30
 MEDIUM          6          0   20
 LOW             0          0   10
```

### `agent-spm inventory`
Browse tool usage across sessions — what tools ran, how often, in how many sessions.

```
Options:
  --path DIR     Override session source directory
  --limit N      Maximum number of sessions to include
```

### `agent-spm events`
Event timeline — every agent action, with filtering.

```
Options:
  --session ID    Filter to a single session
  --elevated      Show only elevated/risky events
  --action TYPE   Filter by action type (shell_exec, file_read, file_write, tool_call)
  --limit N       Limit number of events shown
```

### `agent-spm alerts`
Policy violations sorted by severity.

```
Options:
  --policy PATH   YAML policy file or directory
  --severity SEV  Filter by severity (low, medium, high, critical)
  --limit N       Limit number of alerts shown
```

### `agent-spm report`
Generate a structured Markdown security report.

```
Options:
  --output PATH   Write to file instead of printing to console
  --top N         Maximum violations/events to include (default: 10)
  --policy PATH   YAML policy file or directory
```

## Security Policies

Policies are YAML files. The built-in default policy covers common risks:

| Rule | Severity | What It Catches |
|---|---|---|
| `elevated-shell-command` | HIGH | Shell commands run with elevated flag |
| `sensitive-file-access` | HIGH | Reads to `.env`, `credentials`, SSH keys |
| `force-push` | CRITICAL | `git push --force` to any remote |
| `curl-pipe-bash` | CRITICAL | `curl ... \| bash` execution |
| `destructive-remove` | HIGH | `rm -rf` style commands |

### Writing a Custom Policy

```yaml
name: my-policy
description: Custom rules for my team

rules:
  - name: no-prod-writes
    description: "Agent must not write to production config"
    severity: critical
    match:
      action_types: [file_write]
      path_pattern: "/etc/|/prod/"

  - name: no-network-calls
    description: "Agent must not make outbound network requests"
    severity: high
    match:
      action_types: [shell_exec]
      command_pattern: "curl|wget|fetch"
```

Run with your policy:
```bash
agent-spm alerts --policy my-policy.yaml
agent-spm posture --policy ./policies/
```

### Match Conditions

All conditions in `match:` must be true (AND logic):

| Field | Type | Description |
|---|---|---|
| `action_types` | list | `tool_call`, `file_read`, `file_write`, `shell_exec` |
| `elevated` | bool | Whether the event had elevated permissions |
| `command_pattern` | regex | Matched against shell command |
| `path_pattern` | regex | Matched against file path |

## Posture Scoring

Score starts at 100. Deductions are capped per severity band:

| Severity | Deduction | Cap |
|---|---|---|
| CRITICAL | −20 per alert | max −40 |
| HIGH | −10 per alert | max −30 |
| MEDIUM | −5 per alert | max −20 |
| LOW | −2 per alert | max −10 |

Grades: **A** (90–100) · **B** (75–89) · **C** (60–74) · **D** (45–59) · **F** (0–44)

## Architecture

```
agent_spm/
├── adapters/        Claude Code JSONL parser (swap in other agents here)
├── domain/          Core models: Session, Event, Policy, Alert, PostureScore
├── engine/          Business logic: evaluator, posture scoring, report generation
├── storage/         SQLite repository (only layer touching the database)
├── policies/        YAML loader + built-in default policy
└── cli/             Click commands + Rich TUI
```

Key boundary: `domain/` and `engine/` have **zero** dependencies on storage, CLI, or any framework. The repository pattern means swapping SQLite for Postgres only touches `storage/`.

## Development

```bash
git clone https://github.com/mrsandman17/agentspm.git
cd agentspm
pip install -e ".[dev]"

pytest                        # run all tests
pytest --cov=agent_spm        # with coverage
ruff check . && ruff format . # lint + format
mypy agent_spm/               # type check
```

### Contributing

- TDD: write tests first (red → green → refactor)
- DDD: use the SSPM vocabulary — `Session`, `Event`, `Policy`, `Alert`, `PostureScore`
- Each PR is a shippable increment
- Conventional commits: `feat:`, `fix:`, `test:`, `refactor:`, `docs:`

## License

MIT
