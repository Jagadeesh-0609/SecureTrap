"""Isolated unit tests for LiveJsonLogReader.

Uses only temporary files and controlled writes. Every test bounds
follow() with max_polls so the reader terminates deterministically —
none of these tests can hang. Requires no running Cowrie, no Docker,
no network, no database, and no other external services.
"""

import json
import os

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


def test_file_replacement_with_larger_file_is_read_from_start(tmp_path):
    log_file = _make_empty_log(tmp_path)
    reader = LiveJsonLogReader(log_file, poll_interval=0.01)

    with log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"before": 1}) + "\n")

    first_events = list(reader.follow(max_polls=1))
    assert first_events == [{"before": 1}]

    # Replace the file at the same path with a genuinely different
    # file (different inode), the way real log rotation typically
    # works: write elsewhere, then atomically rename over the old
    # path. The replacement is deliberately much larger than the
    # reader's current position — a size-only truncation check would
    # never flag this as anything but "more data appended".
    replacement_events = [{"new": i} for i in range(20)]
    replacement = tmp_path / "replacement.jsonl"
    replacement.write_text(
        "".join(json.dumps(item) + "\n" for item in replacement_events),
        encoding="utf-8",
    )
    assert replacement.stat().st_size > reader._position
    os.replace(replacement, log_file)

    second_events = list(reader.follow(max_polls=1))

    assert second_events == replacement_events


def test_file_replacement_with_same_size_file_is_read_from_start(tmp_path):
    log_file = _make_empty_log(tmp_path)
    reader = LiveJsonLogReader(log_file, poll_interval=0.01)

    with log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"before": 1}) + "\n")

    first_events = list(reader.follow(max_polls=1))
    assert first_events == [{"before": 1}]
    position_before_replacement = reader._position

    # Same key, single-digit value swapped: guarantees an identical
    # byte length to the original line, so this replacement is
    # exactly as large as the reader's current position — the case a
    # size comparison alone cannot distinguish from "no change".
    replacement_content = json.dumps({"before": 9}) + "\n"
    assert len(replacement_content.encode("utf-8")) == position_before_replacement

    replacement = tmp_path / "replacement.jsonl"
    replacement.write_text(replacement_content, encoding="utf-8")
    assert replacement.stat().st_size == position_before_replacement
    os.replace(replacement, log_file)

    second_events = list(reader.follow(max_polls=1))

    assert second_events == [{"before": 9}]


def test_partial_line_buffer_does_not_leak_into_replacement_file(tmp_path):
    log_file = _make_empty_log(tmp_path)
    reader = LiveJsonLogReader(log_file, poll_interval=0.01)

    # An incomplete line (no trailing newline) gets buffered
    # internally rather than yielded or discarded.
    partial_prefix = '{"before": '
    with log_file.open("a", encoding="utf-8") as f:
        f.write(partial_prefix)

    first_events = list(reader.follow(max_polls=1))
    assert first_events == []
    assert reader._buffer == partial_prefix

    # Replace the file (different inode) with one containing a
    # complete, valid line. If the old buffer leaked into the new
    # file's content, the reader would try to parse
    # '{"before": {"after": 2}\n' — invalid JSON — instead of a clean
    # object, and second_events would come back empty.
    replacement = tmp_path / "replacement.jsonl"
    replacement.write_text(json.dumps({"after": 2}) + "\n", encoding="utf-8")
    os.replace(replacement, log_file)

    second_events = list(reader.follow(max_polls=1))

    assert second_events == [{"after": 2}]
    assert reader._buffer == ""


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