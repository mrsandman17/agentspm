"""Claude Code session log parser.

Reads JSONL session logs from ~/.claude/projects/ and normalizes them
into domain Event and Session objects. This is a read-only log parser —
it never modifies the source files.

Claude Code log format (discovered from real logs):
- Each line is a JSON object with a "type" field
- type="assistant" entries contain tool calls in message.content[]
- Tool call blocks have: type="tool_use", name, input, id
- Each entry has: sessionId, timestamp, cwd, uuid, parentUuid
- Model info is in message.model
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_spm.domain.models import ActionType, Event, Session, Target

# Tools that read files
_READ_TOOLS = frozenset({"Read", "NotebookRead"})

# Tools that write/modify files
_WRITE_TOOLS = frozenset({"Write", "Edit", "NotebookEdit"})

# Tools that execute shell commands
_SHELL_TOOLS = frozenset({"Bash"})

# Tools that search (read-only, not file reads per se)
_SEARCH_TOOLS = frozenset({"Glob", "Grep"})

# Patterns that indicate elevated/risky shell commands
_ELEVATED_COMMAND_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bsudo\b"),
    re.compile(r"\bchmod\s+777\b"),
    re.compile(r"\bchmod\b.*\ba\+[rwx]"),
    re.compile(r"\bchown\b"),
    re.compile(r"\brm\s+-rf\b"),
    re.compile(r"\bgit\s+push\s+--force\b"),
    re.compile(r"\bgit\s+push\s+-f\b"),
    re.compile(r"\bgit\s+reset\s+--hard\b"),
    re.compile(r"\bgit\s+branch\s+-D\b"),
    re.compile(r"\bcurl\b.*\|\s*bash\b"),
    re.compile(r"\bwget\b.*\|\s*bash\b"),
]

# File path patterns that indicate elevated/risky access
_ELEVATED_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\.env$"),
    re.compile(r"\.env\."),
    re.compile(r"\.pem$"),
    re.compile(r"\.key$"),
    re.compile(r"credentials", re.IGNORECASE),
    re.compile(r"secrets?[/\\]", re.IGNORECASE),
    re.compile(r"/etc/(?:passwd|shadow|sudoers)"),
]


def _classify_action(tool_name: str, tool_input: dict[str, Any]) -> ActionType:
    """Determine the ActionType from a tool call."""
    if tool_name in _SHELL_TOOLS:
        return ActionType.SHELL_EXEC
    if tool_name in _READ_TOOLS:
        return ActionType.FILE_READ
    if tool_name in _WRITE_TOOLS:
        return ActionType.FILE_WRITE
    # Search tools and everything else are generic tool calls
    return ActionType.TOOL_CALL


def _extract_target(tool_name: str, tool_input: dict[str, Any]) -> Target:
    """Extract the Target from a tool call's input."""
    path = tool_input.get("file_path") or tool_input.get("notebook_path")
    command = tool_input.get("command")
    return Target(tool_name=tool_name, path=path, command=command)


def _is_elevated_command(command: str) -> bool:
    """Check if a shell command involves elevated/risky operations."""
    return any(p.search(command) for p in _ELEVATED_COMMAND_PATTERNS)


def _is_elevated_path(path: str) -> bool:
    """Check if a file path indicates sensitive resource access."""
    return any(p.search(path) for p in _ELEVATED_PATH_PATTERNS)


def _is_elevated(action_type: ActionType, target: Target) -> bool:
    """Determine if an event involves elevated permissions."""
    if action_type == ActionType.SHELL_EXEC and target.command:
        return _is_elevated_command(target.command)
    if action_type in (ActionType.FILE_READ, ActionType.FILE_WRITE) and target.path:
        return _is_elevated_path(target.path)
    return False


def _parse_timestamp(ts: str) -> datetime:
    """Parse ISO 8601 timestamp from Claude Code logs."""
    # Handle both Z suffix and +00:00
    ts = ts.replace("Z", "+00:00")
    return datetime.fromisoformat(ts)


def parse_jsonl_file(path: Path) -> Session:
    """Parse a single Claude Code JSONL session log into a Session.

    Args:
        path: Path to the .jsonl file.

    Returns:
        A Session object with all parsed Events.
    """
    events: list[Event] = []
    session_id: str | None = None
    model: str | None = None
    cwd: str | None = None
    first_ts: datetime | None = None
    last_ts: datetime | None = None

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Extract session metadata
            if session_id is None and "sessionId" in entry:
                session_id = entry["sessionId"]
            if cwd is None and "cwd" in entry:
                cwd = entry["cwd"]

            # We only care about assistant messages with tool calls
            if entry.get("type") != "assistant":
                continue

            message = entry.get("message", {})
            content = message.get("content", [])
            timestamp_str = entry.get("timestamp")

            # Extract model from first assistant message
            if model is None and message.get("model"):
                model = message["model"]

            if not timestamp_str:
                continue

            ts = _parse_timestamp(timestamp_str)

            # Track session time bounds
            if first_ts is None or ts < first_ts:
                first_ts = ts
            if last_ts is None or ts > last_ts:
                last_ts = ts

            # Process each tool_use block in the message
            if not isinstance(content, list):
                continue

            for block in content:
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    continue

                tool_name = block.get("name", "")
                tool_input = block.get("input", {})

                action_type = _classify_action(tool_name, tool_input)
                target = _extract_target(tool_name, tool_input)
                elevated = _is_elevated(action_type, target)

                event = Event(
                    session_id=session_id or path.stem,
                    timestamp=ts,
                    action_type=action_type,
                    target=target,
                    elevated=elevated,
                    raw=entry,
                )
                events.append(event)

    return Session(
        session_id=session_id or path.stem,
        model=model,
        cwd=cwd,
        started_at=first_ts,
        ended_at=last_ts,
        events=events,
    )


def discover_session_logs(base_dir: Path | None = None) -> list[Path]:
    """Find all Claude Code session JSONL files.

    Args:
        base_dir: Override the default ~/.claude/projects/ directory.

    Returns:
        List of paths to .jsonl files, sorted by modification time (newest first).
    """
    if base_dir is None:
        base_dir = Path.home() / ".claude" / "projects"

    if not base_dir.exists():
        return []

    jsonl_files = list(base_dir.rglob("*.jsonl"))
    # Sort by modification time, newest first
    jsonl_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return jsonl_files


def scan_sessions(
    base_dir: Path | None = None,
    limit: int | None = None,
) -> list[Session]:
    """Scan and parse Claude Code session logs.

    Args:
        base_dir: Override the default log directory.
        limit: Maximum number of sessions to parse.

    Returns:
        List of parsed Sessions with their Events.
    """
    log_files = discover_session_logs(base_dir)
    if limit:
        log_files = log_files[:limit]

    sessions = []
    for path in log_files:
        session = parse_jsonl_file(path)
        if session.events:  # Only include sessions that have tool calls
            sessions.append(session)

    return sessions
