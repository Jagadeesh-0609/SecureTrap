"""Isolated unit tests for DatasetManager.

Uses directly constructed EnrichedEvent objects, temporary paths, and
simple test doubles for DatasetBuilder/DatasetWriter where useful.
Requires no Cowrie, no Docker, no network, no database, no real log
files, and no other external services.
"""

import csv

from core.dataset_manager.builder import DatasetBuilder, DatasetRecord
from core.dataset_manager.manager import DatasetManager
from core.event_engine.event import AttackEvent
from core.log_processor.enricher import EnrichedEvent
from core.log_processor.processor import ProcessedEvent


def _make_enriched_event(
    session_id: str = "ce82815367a4",
    timestamp: str = "2026-08-19T18:00:22.557428Z",
    command: str = "pwd",
    event_type: str = "cowrie.command.input",
    category: str = "command_execution",
) -> EnrichedEvent:
    attack_event = AttackEvent(
        timestamp=timestamp,
        source_ip="127.0.0.1",
        session_id=session_id,
        protocol="ssh",
        command=command,
        event_type=event_type,
        honeypot="Cowrie",
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


def _read_csv_rows(path):
    with path.open("r", encoding="utf-8", newline="") as csv_file:
        return list(csv.reader(csv_file))


class _RecordingBuilder:
    """Fake DatasetBuilder that records what it was asked to build."""

    def __init__(self):
        self.built_events = []

    def build(self, enriched_event):
        self.built_events.append(enriched_event)
        original_event = enriched_event.processed_event.original_event
        return DatasetRecord(
            timestamp=original_event.timestamp,
            source_ip=original_event.source_ip,
            session_id=original_event.session_id,
            protocol=original_event.protocol,
            honeypot=original_event.honeypot,
            event_type=enriched_event.processed_event.event_type,
            category=enriched_event.processed_event.category,
            severity=enriched_event.processed_event.severity,
            command=enriched_event.processed_event.normalized_command,
            has_command=enriched_event.has_command,
            command_length=enriched_event.command_length,
            has_url=enriched_event.has_url,
            has_ip_address=enriched_event.has_ip_address,
            has_file_path=enriched_event.has_file_path,
            has_shell_metacharacters=enriched_event.has_shell_metacharacters,
        )


class _RecordingWriter:
    """Fake DatasetWriter that records what it was asked to write."""

    def __init__(self):
        self.written_records = None
        self.written_path = None

    def write(self, records, path):
        self.written_records = list(records)
        self.written_path = path


def test_single_event_is_converted_and_written(tmp_path):
    destination = tmp_path / "events.csv"
    event = _make_enriched_event(command="pwd")

    DatasetManager().write_events([event], destination)

    rows = _read_csv_rows(destination)
    assert len(rows) == 2  # header + 1 record
    assert "pwd" in rows[1]


def test_multiple_events_are_written_in_input_order(tmp_path):
    destination = tmp_path / "events.csv"
    events = [
        _make_enriched_event(command="pwd"),
        _make_enriched_event(command="ls"),
        _make_enriched_event(command="whoami"),
    ]

    DatasetManager().write_events(events, destination)

    rows = _read_csv_rows(destination)
    command_index = rows[0].index("command")
    commands = [row[command_index] for row in rows[1:]]
    assert commands == ["pwd", "ls", "whoami"]


def test_generator_input_works(tmp_path):
    destination = tmp_path / "events.csv"

    def event_generator():
        yield _make_enriched_event(command="pwd")
        yield _make_enriched_event(command="ls")

    DatasetManager().write_events(event_generator(), destination)

    rows = _read_csv_rows(destination)
    assert len(rows) == 3  # header + 2 records


def test_dataset_builder_is_actually_used(tmp_path):
    fake_builder = _RecordingBuilder()
    events = [_make_enriched_event(command="pwd"), _make_enriched_event(command="ls")]

    DatasetManager(builder=fake_builder, writer=_RecordingWriter()).write_events(
        events, tmp_path / "events.csv"
    )

    assert fake_builder.built_events == events


def test_dataset_writer_is_actually_used(tmp_path):
    fake_writer = _RecordingWriter()
    events = [_make_enriched_event(command="pwd")]
    destination = tmp_path / "events.csv"

    DatasetManager(builder=DatasetBuilder(), writer=fake_writer).write_events(events, destination)

    assert fake_writer.written_path == destination
    assert len(fake_writer.written_records) == 1
    assert isinstance(fake_writer.written_records[0], DatasetRecord)


def test_empty_input_creates_header_only_file_when_missing(tmp_path):
    destination = tmp_path / "events.csv"

    DatasetManager().write_events([], destination)

    rows = _read_csv_rows(destination)
    assert len(rows) == 1  # header only


def test_empty_input_leaves_existing_file_unchanged(tmp_path):
    destination = tmp_path / "events.csv"
    DatasetManager().write_events([_make_enriched_event(command="pwd")], destination)
    before = destination.read_text(encoding="utf-8")

    DatasetManager().write_events([], destination)

    after = destination.read_text(encoding="utf-8")
    assert after == before


def test_dataset_manager_does_not_modify_input_events(tmp_path):
    event = _make_enriched_event(command="pwd")
    original_command = event.processed_event.normalized_command
    original_category = event.processed_event.category

    DatasetManager().write_events([event], tmp_path / "events.csv")

    assert event.processed_event.normalized_command == original_command
    assert event.processed_event.category == original_category


def test_correct_dataset_record_values_reach_the_csv(tmp_path):
    destination = tmp_path / "events.csv"
    event = _make_enriched_event(
        session_id="ce82815367a4",
        timestamp="2026-08-19T18:00:22.557428Z",
        command="pwd",
        event_type="cowrie.command.input",
        category="command_execution",
    )

    DatasetManager().write_events([event], destination)

    rows = _read_csv_rows(destination)
    header, row = rows[0], rows[1]
    record = dict(zip(header, row))
    assert record["session_id"] == "ce82815367a4"
    assert record["timestamp"] == "2026-08-19T18:00:22.557428Z"
    assert record["command"] == "pwd"
    assert record["event_type"] == "cowrie.command.input"
    assert record["category"] == "command_execution"


def test_dependency_injection_works_with_fakes():
    fake_builder = _RecordingBuilder()
    fake_writer = _RecordingWriter()
    events = [_make_enriched_event(command="pwd")]

    manager = DatasetManager(builder=fake_builder, writer=fake_writer)
    manager.write_events(events, "irrelevant/path.csv")

    assert fake_builder.built_events == events
    assert fake_writer.written_path == "irrelevant/path.csv"
    assert len(fake_writer.written_records) == 1