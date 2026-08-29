"""Isolated unit tests for LogProcessor.

Uses directly constructed AttackEvent objects. Requires no Cowrie, no
Docker, no network, no database, no real log files, and no other
external services.
"""

from core.event_engine.event import AttackEvent
from core.log_processor.processor import LogProcessor


def _make_event(event_type: str, command: str = "") -> AttackEvent:
    return AttackEvent(
        timestamp="2026-08-12T14:20:00.123456Z",
        source_ip="127.0.0.1",
        session_id="session001",
        protocol="ssh",
        command=command,
        event_type=event_type,
        honeypot="Cowrie",
    )


def test_command_input_becomes_command_execution():
    processed = LogProcessor().process(_make_event("cowrie.command.input", command="pwd"))
    assert processed.category == "command_execution"


def test_command_failed_becomes_command_execution():
    processed = LogProcessor().process(_make_event("cowrie.command.failed", command="nonexistent"))
    assert processed.category == "command_execution"


def test_login_success_becomes_authentication():
    processed = LogProcessor().process(_make_event("cowrie.login.success"))
    assert processed.category == "authentication"


def test_login_failed_becomes_authentication():
    processed = LogProcessor().process(_make_event("cowrie.login.failed"))
    assert processed.category == "authentication"


def test_session_connect_becomes_session():
    processed = LogProcessor().process(_make_event("cowrie.session.connect"))
    assert processed.category == "session"


def test_session_closed_becomes_session_termination():
    processed = LogProcessor().process(_make_event("cowrie.session.closed"))
    assert processed.category == "session_termination"


def test_client_version_becomes_client_activity():
    processed = LogProcessor().process(_make_event("cowrie.client.version"))
    assert processed.category == "client_activity"


def test_client_kex_becomes_client_activity():
    processed = LogProcessor().process(_make_event("cowrie.client.kex"))
    assert processed.category == "client_activity"


def test_unknown_event_type_becomes_other():
    processed = LogProcessor().process(_make_event("cowrie.some.unmapped.event"))
    assert processed.category == "other"


def test_session_file_download_becomes_file_transfer():
    processed = LogProcessor().process(_make_event("cowrie.session.file_download"))
    assert processed.category == "file_transfer"


def test_log_closed_becomes_logging():
    processed = LogProcessor().process(_make_event("cowrie.log.closed"))
    assert processed.category == "logging"


def test_command_whitespace_is_normalized():
    processed = LogProcessor().process(_make_event("cowrie.command.input", command="  pwd  "))
    assert processed.normalized_command == "pwd"


def test_attacker_input_preserved_exactly_except_whitespace():
    # "whomai" is a typo for "whoami" — the processor must NOT correct it.
    processed = LogProcessor().process(_make_event("cowrie.command.input", command="  whomai  "))
    assert processed.normalized_command == "whomai"


def test_non_command_event_produces_empty_normalized_command():
    processed = LogProcessor().process(_make_event("cowrie.login.success", command=""))
    assert processed.normalized_command == ""


def test_severity_rules_are_applied():
    cases = {
        "cowrie.login.failed": "medium",
        "cowrie.command.failed": "medium",
        "cowrie.command.input": "low",
        "cowrie.session.connect": "low",
        "cowrie.session.closed": "low",
        "cowrie.client.version": "low",
        "cowrie.client.kex": "low",
        "cowrie.login.success": "low",
        "cowrie.some.unmapped.event": "low",
    }

    for event_type, expected_severity in cases.items():
        processed = LogProcessor().process(_make_event(event_type))
        assert processed.severity == expected_severity, event_type


def test_original_attack_event_is_preserved():
    event = _make_event("cowrie.command.input", command="  ls -la  ")
    processed = LogProcessor().process(event)

    assert processed.original_event is event
    assert processed.original_event.timestamp == "2026-08-12T14:20:00.123456Z"
    assert processed.original_event.source_ip == "127.0.0.1"
    assert processed.original_event.session_id == "session001"
    assert processed.original_event.protocol == "ssh"
    assert processed.original_event.command == "  ls -la  "  # unmodified original
    assert processed.original_event.event_type == "cowrie.command.input"
    assert processed.original_event.honeypot == "Cowrie"