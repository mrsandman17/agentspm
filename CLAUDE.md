# Agent SPM — Agent Security Posture Manager

SSPM applied to AI agents. Observe what agents did, evaluate against policies, surface risk.

## SSPM-to-Agent Mapping

| SSPM World | Agent SPM World |
|---|---|
| Users | Agents (session, role, model) |
| SaaS Applications | Tools, MCPs, APIs, file systems |
| Permissions | Agent scopes (what they CAN access) |
| Resources | Files, endpoints, databases, shell commands |
| Security Policies | Permission policies (what they SHOULD access) |
| Posture Score | Agent security posture (drift between can/should) |
| Events (user accessed X) | Events (agent called tool X, read file Y) |
| Overprivileged user | Overprivileged agent (has write, only needs read) |
| Misconfiguration alert | Policy violation alert |

## Architecture

Single-process Python CLI. Decoupled bounded contexts:

1. **Scanning** — parse agent session logs into normalized events
2. **Inventory** — store and query sessions and events (SQLite)
3. **Policy** — load, validate, manage YAML permission policies
4. **Evaluation** — check events against policies, generate alerts
5. **Posture** — calculate security posture scores from evaluation results
6. **Presentation** — TUI rendering (Rich), report generation

```
adapters/          Framework-specific log parsers (Claude Code first)
domain/            Core models + interfaces (zero framework deps)
engine/            Business logic (scanner, evaluator, posture)
storage/           SQLite repositories (only layer touching DB)
policies/          YAML loader, matcher, built-in templates
cli/               Click + Rich TUI
tests/             pytest with fixtures
```

**Key boundary**: `domain/` and `engine/` have ZERO dependencies on storage, CLI, or frameworks. Repository pattern isolates storage. Swap SQLite for Postgres — only `storage/` changes.

## Development Principles

- **DDD**: Use SSPM vocabulary everywhere (Session, Event, Policy, Alert, PostureScore, Inventory)
- **TDD**: Write tests FIRST (red -> green -> refactor). Policy engine is the most critical test suite.
- **Incremental delivery**: Each PR is a shippable, testable increment. Stop after each PR for review.
- **Passive only**: Observe, score, alert. Never block or modify agent behavior.

## Git Workflow

- Small, focused commits. Each commit does ONE thing.
- Conventional commits: `feat:`, `fix:`, `test:`, `refactor:`, `docs:`
- Review your own diff before every commit:
  - No leftover debug prints or TODOs
  - No hardcoded paths or secrets
  - Names match domain vocabulary
  - No dead code or unused imports
- Commits will be squashed on merge — keep them granular during development.
- Open a PR when you finish a feature. Wait for merge confirmation before continuing.

## Security Rules (PUBLIC REPOSITORY)

**NEVER commit**: `.env` files, API keys, tokens, `*.pem`, `*.key`, credentials, database files.

Check every diff before committing. The `.gitignore` must cover:
- `.env`, `*.pem`, `*.key`, `credentials*`, `*.db`, `*.sqlite`

## How to Run

```bash
# Install (development)
pip install -e ".[dev]"

# Run
agent-spm scan
agent-spm inventory
agent-spm events --elevated
agent-spm posture
agent-spm alerts
agent-spm report

# Test
pytest
pytest --cov=agent_spm

# Lint
ruff check .
ruff format .

# Type check
mypy agent_spm/
```

## How to Contribute

- Every PR must include tests proving the feature works
- Tests must pass before opening a PR
- Follow the domain vocabulary — don't invent new terms for existing concepts
- Keep modules decoupled: don't import storage from engine, don't import CLI from domain

## Tech Stack

- Python 3.11+
- Click (CLI) + Rich (TUI)
- PyYAML (policies)
- SQLite (stdlib sqlite3, no ORM)
- pytest + pytest-cov
- ruff (lint/format) + mypy (types)

## AI Agent Instructions

- Use subagents with **sonnet** model to reduce token usage and preserve context
- Read surrounding code first. Match existing patterns and style.
- For non-trivial changes: pause and ask "is there a more elegant way?"
- No temporary fixes. Find root causes. Senior developer standards.

## Project Status

Track project progression in [STATUS.md](./STATUS.md).

### PR Sequence
- [ ] PR 1: Project scaffold + domain models + Claude Code parser + tests
- [ ] PR 2: SQLite storage + inventory/events commands
- [ ] PR 3: Policy engine + evaluation + alerts
- [ ] PR 4: Posture scoring + elevated permission detection
- [ ] PR 5: TUI polish + report generation + README
