"""Isolated unit tests for DatasetWriter.

Uses directly constructed DatasetRecord objects and pytest's tmp_path
fixture exclusively — never the real project-root dataset.csv.
Requires no Cowrie, no Docker, no network, no database, and no other
external services.
"""

import csv

import pytest

from core.dataset_manager.builder import DatasetRecord
from core.dataset_manager.writer import DatasetWriter

_FIELDNAMES = [
    "timestamp",
    "source_ip",
    "session_id",
    "protocol",
    "honeypot",
    "event_type",
    "category",
    "severity",
    "command",
    "has_command",
    "command_length",
    "has_url",
    "has_ip_address",
    "has_file_path",
    "has_shell_metacharacters",
]


def _make_record(**overrides) -> DatasetRecord:
    defaults = dict(
        timestamp="2026-08-19T18:00:22.557428Z",
        source_ip="127.0.0.1",
        session_id="ce82815367a4",
        protocol="ssh",
        honeypot="Cowrie",
        event_type="cowrie.command.input",
        category="command_execution",
        severity="low",
        command="pwd",
        has_command=True,
        command_length=3,
        has_url=False,
        has_ip_address=False,
        has_file_path=False,
        has_shell_metacharacters=False,
    )
    defaults.update(overrides)
    return DatasetRecord(**defaults)


def _read_csv_rows(path):
    with path.open("r", encoding="utf-8", newline="") as csv_file:
        return list(csv.reader(csv_file))


def test_new_file_is_created_with_exact_header(tmp_path):
    destination = tmp_path / "data" / "securetrap_events.csv"
    DatasetWriter().write([], destination)

    rows = _read_csv_rows(destination)
    assert rows[0] == _FIELDNAMES


def test_one_dataset_record_is_written_correctly(tmp_path):
    destination = tmp_path / "events.csv"
    DatasetWriter().write([_make_record()], destination)

    rows = _read_csv_rows(destination)
    assert rows[0] == _FIELDNAMES
    assert rows[1] == [
        "2026-08-19T18:00:22.557428Z",
        "127.0.0.1",
        "ce82815367a4",
        "ssh",
        "Cowrie",
        "cowrie.command.input",
        "command_execution",
        "low",
        "pwd",
        "True",
        "3",
        "False",
        "False",
        "False",
        "False",
    ]


def test_multiple_dataset_records_are_written_in_order(tmp_path):
    destination = tmp_path / "events.csv"
    records = [
        _make_record(command="pwd"),
        _make_record(command="ls"),
        _make_record(command="whoami"),
    ]
    DatasetWriter().write(records, destination)

    rows = _read_csv_rows(destination)
    commands = [row[_FIELDNAMES.index("command")] for row in rows[1:]]
    assert commands == ["pwd", "ls", "whoami"]


def test_existing_data_can_be_appended(tmp_path):
    destination = tmp_path / "events.csv"
    DatasetWriter().write([_make_record(command="first")], destination)
    DatasetWriter().write([_make_record(command="second")], destination)

    rows = _read_csv_rows(destination)
    commands = [row[_FIELDNAMES.index("command")] for row in rows[1:]]
    assert commands == ["first", "second"]


def test_header_is_not_duplicated_during_append(tmp_path):
    destination = tmp_path / "events.csv"
    DatasetWriter().write([_make_record()], destination)
    DatasetWriter().write([_make_record()], destination)

    rows = _read_csv_rows(destination)
    header_rows = [row for row in rows if row == _FIELDNAMES]
    assert len(header_rows) == 1


def test_empty_records_create_header_only_file_when_missing(tmp_path):
    destination = tmp_path / "events.csv"
    DatasetWriter().write([], destination)

    rows = _read_csv_rows(destination)
    assert rows == [_FIELDNAMES]


def test_empty_records_do_not_modify_existing_file(tmp_path):
    destination = tmp_path / "events.csv"
    DatasetWriter().write([_make_record(command="original")], destination)
    before = destination.read_text(encoding="utf-8")

    DatasetWriter().write([], destination)

    after = destination.read_text(encoding="utf-8")
    assert after == before


def test_commands_with_commas_are_preserved_through_csv_quoting(tmp_path):
    destination = tmp_path / "events.csv"
    DatasetWriter().write([_make_record(command="echo a,b,c")], destination)

    rows = _read_csv_rows(destination)
    assert rows[1][_FIELDNAMES.index("command")] == "echo a,b,c"


def test_commands_with_quotes_are_preserved(tmp_path):
    destination = tmp_path / "events.csv"
    DatasetWriter().write([_make_record(command='echo "hello world"')], destination)

    rows = _read_csv_rows(destination)
    assert rows[1][_FIELDNAMES.index("command")] == 'echo "hello world"'


def test_boolean_values_are_serialized_consistently(tmp_path):
    destination = tmp_path / "events.csv"
    DatasetWriter().write([_make_record(has_command=True, has_url=False)], destination)

    rows = _read_csv_rows(destination)
    assert rows[1][_FIELDNAMES.index("has_command")] == "True"
    assert rows[1][_FIELDNAMES.index("has_url")] == "False"


def test_command_length_is_serialized_as_integer_representation(tmp_path):
    destination = tmp_path / "events.csv"
    DatasetWriter().write([_make_record(command="pwd", command_length=3)], destination)

    rows = _read_csv_rows(destination)
    assert rows[1][_FIELDNAMES.index("command_length")] == "3"


def test_parent_directories_are_created_when_necessary(tmp_path):
    destination = tmp_path / "nested" / "data" / "securetrap_events.csv"
    DatasetWriter().write([_make_record()], destination)

    assert destination.exists()


def test_root_level_dataset_csv_is_never_touched(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    legacy_dataset = tmp_path / "dataset.csv"
    legacy_dataset.write_text("command,type\n", encoding="utf-8")

    destination = tmp_path / "data" / "securetrap_events.csv"
    DatasetWriter().write([_make_record()], destination)

    assert legacy_dataset.read_text(encoding="utf-8") == "command,type\n"


def test_existing_correct_header_allows_append(tmp_path):
    destination = tmp_path / "events.csv"
    DatasetWriter().write([_make_record(command="first")], destination)

    DatasetWriter().write([_make_record(command="second")], destination)

    rows = _read_csv_rows(destination)
    commands = [row[_FIELDNAMES.index("command")] for row in rows[1:]]
    assert commands == ["first", "second"]


def test_existing_incorrect_header_raises_value_error(tmp_path):
    destination = tmp_path / "events.csv"
    destination.write_text("command,type\npwd,benign\n", encoding="utf-8")

    with pytest.raises(ValueError):
        DatasetWriter().write([_make_record()], destination)


def test_existing_empty_file_raises_value_error(tmp_path):
    destination = tmp_path / "events.csv"
    destination.touch()

    with pytest.raises(ValueError):
        DatasetWriter().write([_make_record()], destination)