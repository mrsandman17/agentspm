# agent-spm

**Agent Security Posture Manager** — SSPM applied to AI agents.

Observe what your AI agents did, evaluate against security policies, and surface risk. Think security camera, not security guard.

> **Status**: Early development. See [STATUS.md](./STATUS.md) for progress.

## Quick Start

```bash
pip install agent-spm
agent-spm scan        # parse recent Claude Code sessions
agent-spm inventory   # browse sessions with posture scores
agent-spm events      # event timeline
agent-spm posture     # security posture overview
agent-spm alerts      # policy violations
agent-spm report      # generate posture report
```

## What It Does

AI agents run with broad permissions and zero visibility. `agent-spm` scans agent session logs, inventories what happened, evaluates actions against security policies, and shows you which sessions had agents doing risky things.

- **Passive only** — observes, never blocks
- **Local-first** — runs on your machine, no cloud
- **Zero-config start** — `agent-spm scan` works with no policy file
- **Policy-as-code** — YAML policies versioned in git

## License

MIT
