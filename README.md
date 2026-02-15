# agent-spm

**Agent Security Posture Manager** — SSPM applied to AI agents.

> Your AI agent just ran 200 commands. Do you know what happened?

`agent-spm` reads Claude Code session logs, evaluates them against security policies, and scores your posture. Passive observer only — it never modifies agent behavior.

## Who This Is For

Developers using Claude Code or other AI agents who want to **move fast without losing visibility**. Not a security team tool — no blocking, no complex policy language. Just: "here's what your agent did, here's what looks risky."

The real risk isn't individual commands — it's developers granting wide permissions once ("yes to all") without realizing how much the agent is actually doing.

## Quick Start

> **Note:** `agent-spm` is not yet published to PyPI. Install directly from the repository:

```bash
git clone https://github.com/mrsandman17/agentspm.git
cd agentspm
pip install .

# Posture score for all recent sessions
agent-spm posture

# Sessions by project, worst-grade first
agent-spm sessions

# Aggregated alert summary
agent-spm alerts

# Raw event timeline
agent-spm events

# Export a Markdown report
agent-spm report --output report.md
```

## Commands

Commands are ordered from high-level to low-level:

### `agent-spm posture`
The headline number — security posture score (0–100) and grade with alert breakdown.

### `agent-spm sessions`
Sessions grouped by project directory, worst-grade first by default.

```
Options:
  --sort [grade|date|name]   Sort order (default: grade, worst first)
  --limit N                  Maximum sessions to scan
  [SESSION_ID]               Drill into a specific session
```

### `agent-spm alerts`
Policy violations, aggregated by rule by default.

```
Options:
  --detail        Show individual violations instead of aggregated summary
  --severity SEV  Filter by minimum severity (low/medium/high/critical)
  --policy PATH   YAML policy file or directory
  --limit N       Maximum sessions to scan

Sub-commands:
  rules           List all rules with source and status
  add             Interactive wizard to create a custom rule
  remove NAME     Delete a custom rule by name
  clear           Remove all custom rules
  default         Reset to built-in defaults — delete custom.yml
  enable NAME     Enable a disabled rule (works on default rules too)
  disable NAME    Disable a rule without deleting it (works on default rules too)
  test            Dry-run rules against recent sessions
```

**Disabling a noisy default rule:**
```bash
agent-spm alerts disable elevated-shell-command
agent-spm alerts rules   # shows "disabled (override)"
agent-spm alerts enable elevated-shell-command
```

**Adding a custom rule:**
```bash
agent-spm alerts add
# Shows an example rule, then walks you through each field
```

**Dry-run rules without committing:**
```bash
agent-spm alerts test               # test all rules
agent-spm alerts test --rule NAME   # test a specific rule
```

### `agent-spm tools`
Tool usage aggregation — what tools ran, how often, how many sessions.

### `agent-spm events`
Raw event timeline with filtering.

```
Options:
  --path PATH     Override the default ~/.claude/projects/ directory
  --session ID    Filter to a single session
  --elevated      Show only elevated/risky events
  --action TYPE   Filter by action type (shell_exec, file_read, file_write, tool_call)
  --limit N       Maximum number of sessions to scan
```

### `agent-spm report`
Export a Markdown security report.

```
Options:
  --path PATH     Override the default ~/.claude/projects/ directory
  --policy PATH   YAML policy file or directory
  --limit N       Maximum number of sessions to scan
  --top N         Maximum number of top violations and elevated events to include (default: 10)
  --output PATH   Write to file instead of printing to console
```

## Default Security Rules

The built-in policy catches common high-risk patterns:

| Rule | Severity | What It Catches |
|---|---|---|
| `sensitive-file-access` | HIGH | Reads or writes `.env`, `.pem`, `.key`, credentials, `secrets/`, `/etc/passwd` |
| `force-push` | HIGH | `git push --force` — can permanently destroy remote history |
| `elevated-shell-command` | MEDIUM | `sudo`, `chmod 777`, `chown` and other elevated shell commands |
| `destructive-remove` | MEDIUM | `rm -rf` — risk of permanent data loss |

Any rule can be disabled if it's too noisy for your workflow (`agent-spm alerts disable <name>`).

## What Counts as Elevated

Events are flagged as elevated based on the command or file path. Use `--elevated` in `events` or `alerts` to filter to these only.

**Shell commands:**

| Pattern | Example |
|---|---|
| `sudo` | `sudo apt install ...` |
| `chmod 777` or `chmod a+rwx` | `chmod 777 script.sh` |
| `chown` | `chown root file` |
| `rm -rf` | `rm -rf ./dist` |
| `git push --force` / `-f` | `git push --force origin main` |
| `curl ... \| bash` | `curl https://example.com/install.sh \| bash` |
| `wget ... \| bash` | `wget -O- https://example.com/install.sh \| bash` |

**File paths (reads or writes):**

| Pattern | Example |
|---|---|
| `.env`, `.env.*` | `.env`, `.env.production` |
| `.pem` | `server.pem` |
| `.key` | `private.key` |
| `credentials` (case-insensitive) | `~/.aws/credentials` |
| `secrets/` or `secret/` | `secrets/api_key.txt` |
| `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` | `/etc/passwd` |

## Posture Scoring

Score starts at 100. Deductions per alert are capped per severity band:

| Severity | Per Alert | Cap |
|---|---|---|
| CRITICAL | −20 | max −40 |
| HIGH | −10 | max −30 |
| MEDIUM | −3 | max −15 |
| LOW | −1 | max −5 |

Grades: **A** (90–100) · **B** (75–89) · **C** (60–74) · **D** (45–59) · **F** (0–44)

Normal development sessions (file reads/writes, shell commands) typically score B or A. Only sessions with force-pushes or sensitive file access cause significant score drops.

## Custom Policies

```yaml
name: my-policy
description: Custom rules for my team

rules:
  - name: no-prod-deploys
    description: "Flag deployment commands to production"
    severity: critical
    match:
      action_types: [shell_exec]
      command_pattern: "deploy.*prod"

  - name: no-secrets-write
    description: "Agent must not write to secrets directory"
    severity: high
    match:
      action_types: [file_write]
      path_pattern: "secrets/"
```

### Match Conditions (AND logic)

| Field | Type | Description |
|---|---|---|
| `action_types` | list | `tool_call`, `file_read`, `file_write`, `shell_exec` |
| `elevated` | bool | Only match elevated/risky events |
| `command_pattern` | regex | Matched against the shell command |
| `path_pattern` | regex | Matched against the file path |
| `out_of_directory` | bool | File outside session working directory |

## Architecture

```
agent_spm/
├── adapters/        Claude Code JSONL parser
├── domain/          Core models: Session, Event, Policy, Alert, PostureScore
├── engine/          Business logic: evaluator, posture, report
├── policies/        YAML loader + built-in default policy
└── cli/             Click commands + Rich TUI
```

`domain/` and `engine/` have **zero** dependencies on storage, CLI, or any framework.

## Development

```bash
git clone https://github.com/mrsandman17/agentspm.git
cd agentspm
pip install -e ".[dev]"

pytest                        # run all tests
pytest --cov=agent_spm        # with coverage
bash scripts/check.sh         # full pre-push check (lint + format + types + tests)
```

## License

MIT
