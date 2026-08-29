"""Isolated unit tests for AnomalyResultBuilder / AnomalyResult.

Uses directly constructed DatasetRecord objects. Requires no sklearn,
no Cowrie, no Docker, no network, no database, no real log files, and
no other external services.

Note: these tests only verify IsolationForest's own inlier/outlier
semantics (is_anomaly True/False). They never test or claim that
is_anomaly=True means an attack.
"""

import pytest

from core.ai_engine.anomaly_result import AnomalyResultBuilder
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


def test_prediction_one_produces_is_anomaly_false():
    result = AnomalyResultBuilder().build(_make_record(), prediction=1, score=0.1)
    assert result.is_anomaly is False


def test_prediction_minus_one_produces_is_anomaly_true():
    result = AnomalyResultBuilder().build(_make_record(), prediction=-1, score=-0.2)
    assert result.is_anomaly is True


def test_prediction_is_preserved():
    result = AnomalyResultBuilder().build(_make_record(), prediction=-1, score=0.0)
    assert result.prediction == -1


def test_score_is_preserved_as_float():
    result = AnomalyResultBuilder().build(_make_record(), prediction=1, score=0.4567)
    assert result.score == 0.4567
    assert isinstance(result.score, float)


def test_original_dataset_record_is_preserved():
    record = _make_record(command="pwd")
    result = AnomalyResultBuilder().build(record, prediction=1, score=0.1)
    assert result.record is record


def test_invalid_prediction_value_raises_value_error():
    with pytest.raises(ValueError):
        AnomalyResultBuilder().build(_make_record(), prediction=0, score=0.1)


def test_input_dataset_record_is_not_modified():
    record = _make_record(command="pwd", command_length=3)
    original_command = record.command
    original_length = record.command_length

    AnomalyResultBuilder().build(record, prediction=1, score=0.1)

    assert record.command == original_command
    assert record.command_length == original_length


def test_repeated_builds_with_same_input_are_equal():
    record = _make_record(command="pwd")

    first = AnomalyResultBuilder().build(record, prediction=-1, score=-0.3)
    second = AnomalyResultBuilder().build(record, prediction=-1, score=-0.3)

    assert first == second


def test_zero_score_is_accepted():
    result = AnomalyResultBuilder().build(_make_record(), prediction=1, score=0.0)
    assert result.score == 0.0


def test_negative_score_is_accepted():
    result = AnomalyResultBuilder().build(_make_record(), prediction=-1, score=-1.25)
    assert result.score == -1.25


def test_positive_score_is_accepted():
    result = AnomalyResultBuilder().build(_make_record(), prediction=1, score=0.98)
    assert result.score == 0.98


def test_score_is_converted_to_float_from_int_like_value():
    result = AnomalyResultBuilder().build(_make_record(), prediction=1, score=2)
    assert result.score == 2.0
    assert isinstance(result.score, float)