"""Tests for the Claude Code session log parser."""

from pathlib import Path

import pytest

from agent_spm.adapters.claude_code import (
    _is_elevated_command,
    _is_elevated_path,
    parse_jsonl_file,
    scan_sessions,
)
from agent_spm.domain.models import ActionType

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestParseSession:
    """Test parsing a standard session log."""

    @pytest.fixture()
    def session(self):
        return parse_jsonl_file(FIXTURES_DIR / "sample_session.jsonl")

    def test_session_id(self, session):
        assert session.session_id == "test-session-001"

    def test_model_extracted(self, session):
        assert session.model == "claude-sonnet-4-5-20250929"

    def test_cwd_extracted(self, session):
        assert session.cwd == "/Users/dev/myproject"

    def test_timestamps(self, session):
        assert session.started_at is not None
        assert session.ended_at is not None
        assert session.started_at <= session.ended_at

    def test_event_count(self, session):
        # Read, Glob, Edit, Bash, Write = 5 tool calls
        assert session.total_events == 5

    def test_read_event(self, session):
        read_events = [e for e in session.events if e.action_type == ActionType.FILE_READ]
        assert len(read_events) == 1
        assert read_events[0].target.tool_name == "Read"
        assert read_events[0].target.path == "/Users/dev/myproject/src/auth.py"

    def test_write_event(self, session):
        write_events = [e for e in session.events if e.action_type == ActionType.FILE_WRITE]
        # Edit + Write = 2 file writes
        assert len(write_events) == 2

    def test_edit_classified_as_file_write(self, session):
        edit_events = [e for e in session.events if e.target.tool_name == "Edit"]
        assert len(edit_events) == 1
        assert edit_events[0].action_type == ActionType.FILE_WRITE

    def test_shell_exec_event(self, session):
        shell_events = [e for e in session.events if e.action_type == ActionType.SHELL_EXEC]
        assert len(shell_events) == 1
        assert shell_events[0].target.command == "pytest tests/test_auth.py"

    def test_tool_call_event(self, session):
        tool_events = [e for e in session.events if e.action_type == ActionType.TOOL_CALL]
        assert len(tool_events) == 1
        assert tool_events[0].target.tool_name == "Glob"

    def test_no_elevated_events_in_standard_session(self, session):
        assert len(session.elevated_events) == 0


class TestParseElevatedSession:
    """Test parsing a session with elevated/risky operations."""

    @pytest.fixture()
    def session(self):
        return parse_jsonl_file(FIXTURES_DIR / "elevated_session.jsonl")

    def test_session_id(self, session):
        assert session.session_id == "test-session-elevated"

    def test_model(self, session):
        assert session.model == "claude-opus-4-6"

    def test_total_events(self, session):
        # Read .env, sudo, git push --force, Read .pem, chmod 777, curl|bash, rm -rf
        assert session.total_events == 7

    def test_elevated_events_detected(self, session):
        elevated = session.elevated_events
        # .env read, sudo, git push --force, .pem read, chmod 777, curl|bash, rm -rf
        assert len(elevated) == 7

    def test_env_file_read_is_elevated(self, session):
        env_events = [e for e in session.events if e.target.path and ".env" in e.target.path]
        assert len(env_events) == 1
        assert env_events[0].elevated is True

    def test_sudo_command_is_elevated(self, session):
        sudo_events = [e for e in session.events if e.target.command and "sudo" in e.target.command]
        assert len(sudo_events) == 1
        assert sudo_events[0].elevated is True

    def test_force_push_is_elevated(self, session):
        fp_events = [
            e
            for e in session.events
            if e.target.command and "push --force" in (e.target.command or "")
        ]
        assert len(fp_events) == 1
        assert fp_events[0].elevated is True

    def test_pem_file_read_is_elevated(self, session):
        pem_events = [
            e for e in session.events if e.target.path and ".pem" in (e.target.path or "")
        ]
        assert len(pem_events) == 1
        assert pem_events[0].elevated is True


class TestElevatedDetection:
    """Unit tests for elevated pattern matching."""

    @pytest.mark.parametrize(
        "command,expected",
        [
            ("sudo apt install nginx", True),
            ("chmod 777 /etc/passwd", True),
            ("git push --force origin main", True),
            ("git push -f origin main", True),
            ("git reset --hard HEAD~1", True),
            ("git branch -D feature", True),
            ("curl https://example.com | bash", True),
            ("rm -rf /tmp/build", True),
            ("chown root:root /app", True),
            # Safe commands
            ("pytest tests/", False),
            ("git status", False),
            ("git push origin main", False),
            ("npm test", False),
            ("ls -la", False),
            ("git log --oneline", False),
        ],
    )
    def test_elevated_command_detection(self, command, expected):
        assert _is_elevated_command(command) is expected

    @pytest.mark.parametrize(
        "path,expected",
        [
            (".env", True),
            ("/app/.env", True),
            ("/app/.env.production", True),
            ("secrets/api_key.pem", True),
            ("config/server.key", True),
            ("credentials.json", True),
            ("/etc/passwd", True),
            ("/etc/shadow", True),
            # Safe paths
            ("src/auth.py", False),
            ("tests/test_auth.py", False),
            ("README.md", False),
            ("package.json", False),
        ],
    )
    def test_elevated_path_detection(self, path, expected):
        assert _is_elevated_path(path) is expected


class TestScanSessions:
    """Test the scan_sessions function with fixture directory."""

    def test_scan_fixtures_directory(self):
        sessions = scan_sessions(base_dir=FIXTURES_DIR)
        assert len(sessions) == 2

    def test_scan_with_limit(self):
        sessions = scan_sessions(base_dir=FIXTURES_DIR, limit=1)
        assert len(sessions) == 1

    def test_scan_nonexistent_directory(self):
        sessions = scan_sessions(base_dir=Path("/nonexistent"))
        assert sessions == []


class TestEmptyAndMalformedLogs:
    """Test edge cases with empty or malformed log files."""

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.jsonl"
        f.write_text("")
        session = parse_jsonl_file(f)
        assert session.total_events == 0
        assert session.session_id == "empty"

    def test_malformed_json_lines(self, tmp_path):
        f = tmp_path / "bad.jsonl"
        f.write_text("not json\n{invalid\n")
        session = parse_jsonl_file(f)
        assert session.total_events == 0

    def test_no_tool_calls(self, tmp_path):
        f = tmp_path / "no_tools.jsonl"
        f.write_text(
            '{"type":"user","sessionId":"s1","timestamp":"2026-01-01T00:00:00Z",'
            '"message":{"role":"user","content":"hello"}}\n'
        )
        session = parse_jsonl_file(f)
        assert session.total_events == 0
        assert session.session_id == "s1"
