"""Isolated unit tests for SessionAggregator.

Uses directly constructed AttackEvent / ProcessedEvent / EnrichedEvent
objects. Requires no Cowrie, no Docker, no network, no database, no
real log files, and no other external services.
"""

import pytest

from core.event_engine.event import AttackEvent
from core.log_processor.enricher import EnrichedEvent
from core.log_processor.processor import ProcessedEvent
from core.log_processor.session import SessionAggregator, SessionSummary


def _make_enriched_event(
    session_id: str,
    source_ip: str,
    protocol: str,
    honeypot: str,
    timestamp: str,
    event_type: str,
    category: str,
    command: str = "",
) -> EnrichedEvent:
    attack_event = AttackEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        session_id=session_id,
        protocol=protocol,
        command=command,
        event_type=event_type,
        honeypot=honeypot,
    )
    processed_event = ProcessedEvent(
        original_event=attack_event,
        event_type=event_type,
        normalized_command=command,
        category=category,
        severity="low",
    )
    return EnrichedEvent(
        processed_event=processed_event,
        has_command=bool(command),
        command_length=len(command),
        has_url=False,
        has_ip_address=False,
        has_file_path=False,
        has_shell_metacharacters=False,
    )


def test_single_event_creates_valid_session_summary():
    event = _make_enriched_event(
        "sess1", "127.0.0.1", "ssh", "Cowrie",
        "2026-08-19T18:00:00.000000Z", "cowrie.session.connect", "session",
    )

    summary = SessionAggregator().aggregate([event])

    assert isinstance(summary, SessionSummary)
    assert summary.event_count == 1


def test_multiple_events_are_aggregated_correctly():
    events = [
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:00.000000Z", "cowrie.session.connect", "session",
        ),
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:05.000000Z", "cowrie.login.success", "authentication",
        ),
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:10.000000Z", "cowrie.command.input", "command_execution", "pwd",
        ),
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:15.000000Z", "cowrie.session.closed", "session_termination",
        ),
    ]

    summary = SessionAggregator().aggregate(events)

    assert summary.event_count == 4
    assert summary.command_count == 1
    assert summary.login_success_count == 1
    assert summary.login_failure_count == 0


def test_earliest_timestamp_becomes_start_time():
    events = [
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:30.000000Z", "cowrie.command.input", "command_execution", "pwd",
        ),
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:10.000000Z", "cowrie.session.connect", "session",
        ),
    ]

    summary = SessionAggregator().aggregate(events)

    assert summary.start_time == "2026-08-19T18:00:10.000000Z"


def test_latest_timestamp_becomes_end_time():
    events = [
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:10.000000Z", "cowrie.session.connect", "session",
        ),
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:30.000000Z", "cowrie.session.closed", "session_termination",
        ),
    ]

    summary = SessionAggregator().aggregate(events)

    assert summary.end_time == "2026-08-19T18:00:30.000000Z"


def test_event_count_is_correct():
    events = [
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            f"2026-08-19T18:00:{i:02d}.000000Z", "cowrie.command.input", "command_execution", "pwd",
        )
        for i in range(5)
    ]

    summary = SessionAggregator().aggregate(events)

    assert summary.event_count == 5


def test_command_count_is_correct():
    events = [
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:00.000000Z", "cowrie.session.connect", "session",
        ),
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:01.000000Z", "cowrie.command.input", "command_execution", "pwd",
        ),
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:02.000000Z", "cowrie.command.input", "command_execution", "ls",
        ),
    ]

    summary = SessionAggregator().aggregate(events)

    assert summary.command_count == 2


def test_successful_login_count_is_correct():
    events = [
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:00.000000Z", "cowrie.login.success", "authentication",
        ),
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:01.000000Z", "cowrie.login.success", "authentication",
        ),
    ]

    summary = SessionAggregator().aggregate(events)

    assert summary.login_success_count == 2


def test_failed_login_count_is_correct():
    events = [
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:00.000000Z", "cowrie.login.failed", "authentication",
        ),
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:01.000000Z", "cowrie.login.failed", "authentication",
        ),
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:02.000000Z", "cowrie.login.failed", "authentication",
        ),
    ]

    summary = SessionAggregator().aggregate(events)

    assert summary.login_failure_count == 3


def test_session_id_is_preserved():
    event = _make_enriched_event(
        "ce82815367a4", "127.0.0.1", "ssh", "Cowrie",
        "2026-08-19T18:00:00.000000Z", "cowrie.session.connect", "session",
    )

    summary = SessionAggregator().aggregate([event])

    assert summary.session_id == "ce82815367a4"


def test_source_ip_protocol_honeypot_are_preserved():
    event = _make_enriched_event(
        "sess1", "10.0.0.5", "telnet", "Dionaea",
        "2026-08-19T18:00:00.000000Z", "dionaea.session.connect", "session",
    )

    summary = SessionAggregator().aggregate([event])

    assert summary.source_ip == "10.0.0.5"
    assert summary.protocol == "telnet"
    assert summary.honeypot == "Dionaea"


def test_empty_input_raises_value_error():
    with pytest.raises(ValueError):
        SessionAggregator().aggregate([])


def test_mixed_session_ids_raise_value_error():
    events = [
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:00.000000Z", "cowrie.session.connect", "session",
        ),
        _make_enriched_event(
            "sess2", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:01.000000Z", "cowrie.command.input", "command_execution", "pwd",
        ),
    ]

    with pytest.raises(ValueError):
        SessionAggregator().aggregate(events)


def test_inconsistent_source_ip_raises_value_error():
    events = [
        _make_enriched_event(
            "sess1", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:00.000000Z", "cowrie.session.connect", "session",
        ),
        _make_enriched_event(
            "sess1", "10.0.0.9", "ssh", "Cowrie",
            "2026-08-19T18:00:01.000000Z", "cowrie.command.input", "command_execution", "pwd",
        ),
    ]

    with pytest.raises(ValueError):
        SessionAggregator().aggregate(events)


def test_real_cowrie_session_produces_expected_summary():
    # The 11 real events observed for session ce82815367a4.
    events = [
        _make_enriched_event(
            "ce82815367a4", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:22.557428Z", "cowrie.session.connect", "session",
        ),
        _make_enriched_event(
            "ce82815367a4", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:23.000000Z", "cowrie.client.version", "client_activity",
        ),
        _make_enriched_event(
            "ce82815367a4", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:23.500000Z", "cowrie.client.kex", "client_activity",
        ),
        _make_enriched_event(
            "ce82815367a4", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:25.000000Z", "cowrie.login.success", "authentication",
        ),
        _make_enriched_event(
            "ce82815367a4", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:25.500000Z", "cowrie.client.size", "client_activity",
        ),
        _make_enriched_event(
            "ce82815367a4", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:26.000000Z", "cowrie.client.var", "client_activity",
        ),
        _make_enriched_event(
            "ce82815367a4", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:26.500000Z", "cowrie.client.var", "client_activity",
        ),
        _make_enriched_event(
            "ce82815367a4", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:00:27.000000Z", "cowrie.session.params", "session",
        ),
        _make_enriched_event(
            "ce82815367a4", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:02:10.000000Z", "cowrie.command.input", "command_execution", "pwd",
        ),
        _make_enriched_event(
            "ce82815367a4", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:03:15.000000Z", "cowrie.command.input", "command_execution", "pwd",
        ),
        _make_enriched_event(
            "ce82815367a4", "127.0.0.1", "ssh", "Cowrie",
            "2026-08-19T18:04:42.103477Z", "cowrie.session.closed", "session_termination",
        ),
    ]

    summary = SessionAggregator().aggregate(events)

    assert summary.session_id == "ce82815367a4"
    assert summary.source_ip == "127.0.0.1"
    assert summary.protocol == "ssh"
    assert summary.honeypot == "Cowrie"
    assert summary.event_count == 11
    assert summary.command_count == 2
    assert summary.login_success_count == 1
    assert summary.login_failure_count == 0
    assert summary.start_time == "2026-08-19T18:00:22.557428Z"
    assert summary.end_time == "2026-08-19T18:04:42.103477Z"