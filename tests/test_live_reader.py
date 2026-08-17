"""Isolated unit tests for LiveJsonLogReader.

Uses only temporary files and controlled writes. Every test bounds
follow() with max_polls so the reader terminates deterministically —
none of these tests can hang. Requires no running Cowrie, no Docker,
no network, no database, and no other external services.
"""

import json

import pytest

from core.honeypot_engine.live_reader import DEFAULT_POLL_INTERVAL, LiveJsonLogReader


def _make_empty_log(tmp_path):
    log_file = tmp_path / "live.jsonl"
    log_file.write_text("", encoding="utf-8")
    return log_file


def test_detects_newly_appended_valid_json(tmp_path):
    log_file = _make_empty_log(tmp_path)
    reader = LiveJsonLogReader(log_file, poll_interval=0.01)

    with log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"a": 1}) + "\n")

    events = list(reader.follow(max_polls=1))

    assert events == [{"a": 1}]


def test_blank_lines_are_ignored(tmp_path):
    log_file = _make_empty_log(tmp_path)
    reader = LiveJsonLogReader(log_file, poll_interval=0.01)

    with log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"a": 1}) + "\n")
        f.write("\n")
        f.write("   \n")
        f.write(json.dumps({"b": 2}) + "\n")

    events = list(reader.follow(max_polls=1))

    assert events == [{"a": 1}, {"b": 2}]


def test_malformed_line_is_skipped_and_recorded(tmp_path):
    log_file = _make_empty_log(tmp_path)
    reader = LiveJsonLogReader(log_file, poll_interval=0.01)

    with log_file.open("a", encoding="utf-8") as f:
        f.write("{not valid json\n")

    events = list(reader.follow(max_polls=1))

    assert events == []
    assert len(reader.malformed_lines) == 1


def test_valid_line_after_malformed_line_is_processed(tmp_path):
    log_file = _make_empty_log(tmp_path)
    reader = LiveJsonLogReader(log_file, poll_interval=0.01)

    with log_file.open("a", encoding="utf-8") as f:
        f.write("{not valid json\n")
        f.write(json.dumps({"ok": True}) + "\n")

    events = list(reader.follow(max_polls=1))

    assert events == [{"ok": True}]
    assert len(reader.malformed_lines) == 1


def test_non_object_json_values_are_ignored(tmp_path):
    log_file = _make_empty_log(tmp_path)
    reader = LiveJsonLogReader(log_file, poll_interval=0.01)

    with log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps([1, 2, 3]) + "\n")
        f.write(json.dumps("just a string") + "\n")
        f.write(json.dumps(42) + "\n")
        f.write(json.dumps({"valid": True}) + "\n")

    events = list(reader.follow(max_polls=1))

    assert events == [{"valid": True}]


def test_truncation_does_not_crash_and_new_data_is_picked_up(tmp_path):
    log_file = _make_empty_log(tmp_path)
    reader = LiveJsonLogReader(log_file, poll_interval=0.01)

    with log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"before": 1}) + "\n")

    first_events = list(reader.follow(max_polls=1))
    assert first_events == [{"before": 1}]

    # Simulate truncation/rotation: file shrinks below the reader's position.
    log_file.write_text("", encoding="utf-8")
    with log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"after": 2}) + "\n")

    second_events = list(reader.follow(max_polls=1))
    assert second_events == [{"after": 2}]


def test_polling_interval_is_configurable(tmp_path):
    log_file = _make_empty_log(tmp_path)

    custom_reader = LiveJsonLogReader(log_file, poll_interval=5.0)
    default_reader = LiveJsonLogReader(log_file)

    assert custom_reader.poll_interval == 5.0
    assert default_reader.poll_interval == DEFAULT_POLL_INTERVAL


def test_reader_does_not_require_cowrie_fields(tmp_path):
    log_file = _make_empty_log(tmp_path)
    reader = LiveJsonLogReader(log_file, poll_interval=0.01)

    with log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"anything": "goes", "no_eventid_here": True}) + "\n")

    events = list(reader.follow(max_polls=1))

    assert events == [{"anything": "goes", "no_eventid_here": True}]


def test_returns_dictionaries_only(tmp_path):
    log_file = _make_empty_log(tmp_path)
    reader = LiveJsonLogReader(log_file, poll_interval=0.01)

    with log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"a": 1}) + "\n")
        f.write(json.dumps([1, 2]) + "\n")
        f.write(json.dumps({"b": 2}) + "\n")

    events = list(reader.follow(max_polls=1))

    assert all(isinstance(event, dict) for event in events)
    assert events == [{"a": 1}, {"b": 2}]


def test_missing_file_raises_file_not_found(tmp_path):
    missing_file = tmp_path / "does_not_exist.jsonl"

    with pytest.raises(FileNotFoundError):
        LiveJsonLogReader(missing_file)