"""Tests for the SecureTrap JSONL log reader."""

import json

import pytest

from core.honeypot_engine.log_reader import JsonLogReader


def write_lines(path, lines):
    """Write test lines to a temporary file."""
    path.write_text("\n".join(lines), encoding="utf-8")


def test_multiple_valid_lines_are_read(tmp_path):
    log_file = tmp_path / "events.jsonl"

    write_lines(
        log_file,
        [
            json.dumps({"a": 1}),
            json.dumps({"b": 2}),
            json.dumps({"c": 3}),
        ],
    )

    events = list(JsonLogReader(log_file).read_events())

    assert events == [{"a": 1}, {"b": 2}, {"c": 3}]


def test_each_result_is_a_dict(tmp_path):
    log_file = tmp_path / "events.jsonl"

    write_lines(
        log_file,
        [json.dumps({"key": "value"})],
    )

    events = list(JsonLogReader(log_file).read_events())

    assert all(isinstance(event, dict) for event in events)


def test_blank_lines_are_ignored(tmp_path):
    log_file = tmp_path / "events.jsonl"

    write_lines(
        log_file,
        [
            json.dumps({"a": 1}),
            "",
            "   ",
            json.dumps({"b": 2}),
        ],
    )

    events = list(JsonLogReader(log_file).read_events())

    assert events == [{"a": 1}, {"b": 2}]


def test_empty_file_produces_no_events(tmp_path):
    log_file = tmp_path / "events.jsonl"
    log_file.write_text("", encoding="utf-8")

    events = list(JsonLogReader(log_file).read_events())

    assert events == []


def test_invalid_json_line_does_not_stop_later_lines(tmp_path):
    log_file = tmp_path / "events.jsonl"

    write_lines(
        log_file,
        [
            json.dumps({"a": 1}),
            "{not valid json",
            json.dumps({"b": 2}),
        ],
    )

    reader = JsonLogReader(log_file)
    events = list(reader.read_events())

    assert events == [{"a": 1}, {"b": 2}]
    assert len(reader.malformed_lines) == 1
    assert reader.malformed_lines[0].line_number == 2


def test_missing_file_raises_file_not_found(tmp_path):
    missing_file = tmp_path / "does_not_exist.jsonl"

    reader = JsonLogReader(missing_file)

    with pytest.raises(FileNotFoundError):
        list(reader.read_events())


def test_mixed_valid_and_invalid_lines_preserve_valid_events(tmp_path):
    log_file = tmp_path / "events.jsonl"

    write_lines(
        log_file,
        [
            json.dumps({"eventid": "one"}),
            "not json at all",
            "",
            json.dumps({"eventid": "two"}),
            "{broken",
            json.dumps({"eventid": "three"}),
        ],
    )

    reader = JsonLogReader(log_file)
    events = list(reader.read_events())

    assert events == [
        {"eventid": "one"},
        {"eventid": "two"},
        {"eventid": "three"},
    ]

    assert len(reader.malformed_lines) == 2


def test_non_object_json_is_skipped(tmp_path):
    log_file = tmp_path / "events.jsonl"

    write_lines(
        log_file,
        [
            json.dumps({"eventid": "valid"}),
            json.dumps(["not", "an", "object"]),
            json.dumps("just a string"),
            json.dumps({"eventid": "valid2"}),
        ],
    )

    reader = JsonLogReader(log_file)
    events = list(reader.read_events())

    assert events == [
        {"eventid": "valid"},
        {"eventid": "valid2"},
    ]

    assert len(reader.malformed_lines) == 2