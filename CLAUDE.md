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
agent-spm tools
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

## Pre-Push Checklist

**Before every push, run `scripts/check.sh`. It mirrors CI exactly — if it passes locally, CI passes.**

```bash
bash scripts/check.sh
```

`scripts/check.sh` runs the four steps from `.github/workflows/ci.yml` in order:
1. `ruff check .` — lint
2. `ruff format --check .` — formatting (run `ruff format .` to auto-fix)
3. `mypy agent_spm/` — strict type checking
4. `pytest --cov=agent_spm --cov-report=term-missing` — full test suite

Keep `scripts/check.sh` in sync with `.github/workflows/ci.yml` if CI ever changes.

## How to Contribute

- Every PR must include tests proving the feature works
- Run the pre-push checklist above before opening a PR
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

### Context Management
- Delegate noisy operations (running tests, log parsing) to subagents — only the summary returns to context
- Reference docs live in separate `.md` files; CLAUDE.md just tells the model when to read them
- Keep CLAUDE.md short. Move stable reference material (schemas, specs, runbooks) to topic files

### Code Standards
- Read surrounding code first. Match existing patterns and style.
- For non-trivial changes: pause and ask "is there a more elegant way?"
- No temporary fixes. Find root causes. Senior developer standards.

## Project Status

Track project progression in [STATUS.md](./STATUS.md).
