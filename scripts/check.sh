#!/usr/bin/env bash
# Local mirror of CI checks (.github/workflows/ci.yml).
# Run this before every push. All four steps must pass.
set -euo pipefail

echo "==> ruff check"
ruff check .

echo "==> ruff format --check"
ruff format --check .

echo "==> mypy"
mypy agent_spm/

echo "==> pytest"
pytest --cov=agent_spm --cov-report=term-missing

echo ""
echo "All checks passed."
