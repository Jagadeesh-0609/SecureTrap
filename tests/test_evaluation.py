"""Isolated unit tests for AnomalyEvaluator / EvaluationReport.

Uses directly constructed AnomalyResult objects with simple
DatasetRecord objects. Requires no sklearn, no Cowrie, no Docker, no
network, no database, no real log files, and no other external
services.

Note: assertions here are purely structural/numerical. None of these
tests claim, or could be read as claiming, that a given result is a
real attack.
"""

import dataclasses

from core.ai_engine.anomaly_result import AnomalyResult
from core.ai_engine.evaluation import AnomalyEvaluator, EvaluationReport
from core.dataset_manager.builder import DatasetRecord


def _make_record(command: str = "pwd") -> DatasetRecord:
    return DatasetRecord(
        timestamp="2026-08-19T18:00:22.557428Z",
        source_ip="127.0.0.1",
        session_id="ce82815367a4",
        protocol="ssh",
        honeypot="Cowrie",
        event_type="cowrie.command.input",
        category="command_execution",
        severity="low",
        command=command,
        has_command=True,
        command_length=len(command),
        has_url=False,
        has_ip_address=False,
        has_file_path=False,
        has_shell_metacharacters=False,
    )


def _make_result(prediction: int, score: float, command: str = "pwd") -> AnomalyResult:
    return AnomalyResult(
        record=_make_record(command=command),
        prediction=prediction,
        score=score,
        is_anomaly=(prediction == -1),
    )


def test_empty_input_returns_expected_zero_report():
    report = AnomalyEvaluator().evaluate([])

    assert report.total_count == 0
    assert report.normal_count == 0
    assert report.anomaly_count == 0
    assert report.anomaly_rate == 0.0
    assert report.min_score is None
    assert report.max_score is None
    assert report.mean_score is None


def test_all_normal_results_are_counted_correctly():
    results = [_make_result(1, 0.1), _make_result(1, 0.2), _make_result(1, 0.3)]
    report = AnomalyEvaluator().evaluate(results)

    assert report.total_count == 3
    assert report.normal_count == 3
    assert report.anomaly_count == 0


def test_all_anomaly_results_are_counted_correctly():
    results = [_make_result(-1, -0.1), _make_result(-1, -0.2)]
    report = AnomalyEvaluator().evaluate(results)

    assert report.total_count == 2
    assert report.normal_count == 0
    assert report.anomaly_count == 2


def test_mixed_normal_and_anomaly_results_are_counted_correctly():
    results = [
        _make_result(1, 0.1),
        _make_result(-1, -0.5),
        _make_result(1, 0.3),
        _make_result(-1, -0.2),
    ]
    report = AnomalyEvaluator().evaluate(results)

    assert report.total_count == 4
    assert report.normal_count == 2
    assert report.anomaly_count == 2


def test_anomaly_rate_is_calculated_correctly():
    results = [_make_result(1, 0.1)] * 8 + [_make_result(-1, -0.1)] * 2
    report = AnomalyEvaluator().evaluate(results)

    assert report.anomaly_rate == 0.2


def test_minimum_score_is_calculated_correctly():
    results = [_make_result(1, 0.5), _make_result(-1, -0.9), _make_result(1, 0.2)]
    report = AnomalyEvaluator().evaluate(results)

    assert report.min_score == -0.9


def test_maximum_score_is_calculated_correctly():
    results = [_make_result(1, 0.5), _make_result(-1, -0.9), _make_result(1, 0.8)]
    report = AnomalyEvaluator().evaluate(results)

    assert report.max_score == 0.8


def test_mean_score_is_calculated_correctly():
    results = [_make_result(1, 1.0), _make_result(1, 2.0), _make_result(1, 3.0)]
    report = AnomalyEvaluator().evaluate(results)

    assert report.mean_score == 2.0


def test_single_result_works_correctly():
    results = [_make_result(-1, -0.42)]
    report = AnomalyEvaluator().evaluate(results)

    assert report.total_count == 1
    assert report.anomaly_count == 1
    assert report.normal_count == 0
    assert report.anomaly_rate == 1.0
    assert report.min_score == -0.42
    assert report.max_score == -0.42
    assert report.mean_score == -0.42


def test_negative_and_positive_scores_are_handled_correctly():
    results = [_make_result(1, 0.75), _make_result(-1, -0.75)]
    report = AnomalyEvaluator().evaluate(results)

    assert report.min_score == -0.75
    assert report.max_score == 0.75
    assert report.mean_score == 0.0


def test_evaluation_does_not_modify_input_results():
    results = [_make_result(1, 0.1), _make_result(-1, -0.2)]
    original_predictions = [result.prediction for result in results]
    original_scores = [result.score for result in results]

    AnomalyEvaluator().evaluate(results)

    assert [result.prediction for result in results] == original_predictions
    assert [result.score for result in results] == original_scores


def test_underlying_dataset_record_identity_remains_untouched():
    result = _make_result(1, 0.1, command="pwd")
    original_record = result.record

    AnomalyEvaluator().evaluate([result])

    assert result.record is original_record


def test_repeated_evaluation_is_deterministic():
    results = [_make_result(1, 0.1), _make_result(-1, -0.3), _make_result(1, 0.4)]

    first = AnomalyEvaluator().evaluate(results)
    second = AnomalyEvaluator().evaluate(results)

    assert first == second


def test_generator_input_works():
    def result_generator():
        yield _make_result(1, 0.1)
        yield _make_result(-1, -0.2)

    report = AnomalyEvaluator().evaluate(result_generator())

    assert report.total_count == 2
    assert report.anomaly_count == 1


def test_no_supervised_metrics_or_labels_are_introduced():
    report_fields = {field.name for field in dataclasses.fields(EvaluationReport)}
    forbidden = {
        "attack_count",
        "benign_count",
        "true_positive",
        "false_positive",
        "accuracy",
        "precision",
        "recall",
        "f1",
        "auc",
        "confidence",
        "threat_level",
    }
    assert report_fields.isdisjoint(forbidden)
    assert report_fields == {
        "total_count",
        "normal_count",
        "anomaly_count",
        "anomaly_rate",
        "min_score",
        "max_score",
        "mean_score",
    }