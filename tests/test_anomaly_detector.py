"""Isolated unit tests for AnomalyDetector.

Uses small, hand-built FeatureMatrix objects only. Requires no
Cowrie, no Docker, no network, no database, no real log files, and no
other external services. Assertions are structural (output shape,
valid prediction values, determinism, a controlled synthetic anomaly
case) rather than pinned to exact sklearn scores.
"""

import copy

import pytest
from sklearn.ensemble import IsolationForest

from core.ai_engine.anomaly_detector import AnomalyDetector
from core.ai_engine.feature_matrix import FEATURE_NAMES, FeatureMatrix


def _make_matrix(rows):
    return FeatureMatrix(feature_names=FEATURE_NAMES, rows=list(rows))


def _cluster_with_one_outlier():
    """Nine similar 'normal' rows plus one deliberately extreme row."""
    normal_rows = [(3, 1, 0, 0, 0, 0)] * 9
    outlier_row = (500, 1, 1, 1, 1, 1)
    return _make_matrix(normal_rows + [outlier_row])


def test_detector_can_be_fitted_on_a_non_empty_matrix():
    matrix = _cluster_with_one_outlier()
    detector = AnomalyDetector(random_state=42)

    detector.fit(matrix)  # should not raise

    # A subsequent call succeeding confirms fit() actually took effect.
    predictions = detector.predict(matrix)
    assert len(predictions) == len(matrix.rows)


def test_score_returns_one_value_per_input_row():
    matrix = _cluster_with_one_outlier()
    detector = AnomalyDetector(random_state=42)
    detector.fit(matrix)

    scores = detector.score(matrix)

    assert len(scores) == len(matrix.rows)


def test_predict_returns_one_value_per_input_row():
    matrix = _cluster_with_one_outlier()
    detector = AnomalyDetector(random_state=42)
    detector.fit(matrix)

    predictions = detector.predict(matrix)

    assert len(predictions) == len(matrix.rows)


def test_predictions_contain_only_minus_one_and_one():
    matrix = _cluster_with_one_outlier()
    detector = AnomalyDetector(contamination=0.1, random_state=42)
    detector.fit(matrix)

    predictions = detector.predict(matrix)

    assert set(predictions) <= {1, -1}


def test_predict_and_score_before_fit_raise_clear_error():
    matrix = _cluster_with_one_outlier()
    detector = AnomalyDetector(random_state=42)

    with pytest.raises(RuntimeError):
        detector.predict(matrix)

    with pytest.raises(RuntimeError):
        detector.score(matrix)


def test_empty_matrix_fit_raises_value_error():
    empty_matrix = _make_matrix([])
    detector = AnomalyDetector(random_state=42)

    with pytest.raises(ValueError):
        detector.fit(empty_matrix)


def test_repeated_runs_with_same_random_state_are_deterministic():
    matrix = _cluster_with_one_outlier()

    detector_a = AnomalyDetector(contamination=0.1, random_state=42)
    detector_a.fit(matrix)

    detector_b = AnomalyDetector(contamination=0.1, random_state=42)
    detector_b.fit(matrix)

    assert detector_a.predict(matrix) == detector_b.predict(matrix)
    assert detector_a.score(matrix) == detector_b.score(matrix)


def test_feature_ordering_is_respected():
    rows = [
        (10, 1, 0, 1, 0, 1),
        (2, 0, 0, 0, 0, 0),
        (5, 1, 1, 0, 0, 0),
        (50, 1, 1, 1, 1, 1),
    ]
    matrix = _make_matrix(rows)

    detector = AnomalyDetector(contamination=0.25, random_state=42)
    detector.fit(matrix)
    detector_predictions = detector.predict(matrix)

    # A raw IsolationForest fed the exact same row order, with the same
    # hyperparameters, must agree — proving AnomalyDetector passes
    # matrix.rows through untouched rather than reordering columns.
    reference_model = IsolationForest(contamination=0.25, random_state=42)
    reference_model.fit(rows)
    reference_predictions = list(reference_model.predict(rows))

    assert detector_predictions == reference_predictions


def test_input_feature_matrix_is_not_modified():
    matrix = _cluster_with_one_outlier()
    rows_before = copy.deepcopy(matrix.rows)
    feature_names_before = matrix.feature_names

    detector = AnomalyDetector(contamination=0.1, random_state=42)
    detector.fit(matrix)
    detector.predict(matrix)
    detector.score(matrix)

    assert matrix.rows == rows_before
    assert matrix.feature_names == feature_names_before


def test_synthetic_outlier_produces_anomaly_with_explicit_contamination():
    matrix = _cluster_with_one_outlier()
    detector = AnomalyDetector(contamination=0.1, random_state=42)
    detector.fit(matrix)

    predictions = detector.predict(matrix)

    assert -1 in predictions


def test_detector_does_not_return_probability_values():
    matrix = _cluster_with_one_outlier()
    detector = AnomalyDetector(contamination=0.1, random_state=42)
    detector.fit(matrix)

    scores = detector.score(matrix)

    # A probability could never be negative; decision_function scores
    # for a clear outlier like this one routinely are.
    assert any(value < 0 for value in scores)
    assert not hasattr(detector, "predict_proba")


def test_constructor_parameters_are_preserved():
    detector = AnomalyDetector(contamination=0.15, random_state=7)

    assert detector.contamination == 0.15
    assert detector.random_state == 7

    default_detector = AnomalyDetector()
    assert default_detector.contamination == "auto"
    assert default_detector.random_state == 42