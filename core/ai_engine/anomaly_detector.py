"""AI Engine — Anomaly Detector for SecureTrap.

A small, testable wrapper around scikit-learn's IsolationForest,
operating only on the existing FeatureMatrix. There is no verified
ground-truth label data for the current dataset, so this is
unsupervised anomaly detection — no supervised classifier is used,
and no "attack"/"benign" label is ever invented. IsolationForest's own
inlier/outlier semantics are preserved exactly, never relabeled.

This module consumes FeatureMatrix only. It does not read logs, parse
CSV/JSON, call any reader/adapter/ingestion/log-processing/dataset
component, or know about any honeypot's raw fields.
"""

from typing import List, Union

from sklearn.ensemble import IsolationForest

from core.ai_engine.feature_matrix import FeatureMatrix


class AnomalyDetector:
    """Wraps sklearn's IsolationForest for SecureTrap's FeatureMatrix.

    Preserves IsolationForest's own semantics rather than inventing
    SecureTrap-specific labels:

        predict() ->  1 = inlier / normal
                     -1 = outlier / anomaly

        score()   -> sklearn's decision_function() value for each row:
                     higher means more "normal", lower (more negative)
                     means more anomalous, centered on the model's
                     decision boundary. This is not a probability.

    fit()/score()/predict() all operate on `matrix.rows` directly and
    in order — feature columns are never reordered, dropped, or
    reinterpreted.
    """

    def __init__(self, contamination: Union[str, float] = "auto", random_state: int = 42) -> None:
        """Create an AnomalyDetector.

        Args:
            contamination: Passed directly to IsolationForest's
                `contamination` parameter (the expected proportion of
                anomalies in the data). Defaults to "auto".
            random_state: Passed directly to IsolationForest's
                `random_state` parameter, so fitting and scoring are
                deterministic for a given FeatureMatrix. Defaults to
                42.
        """
        self.contamination = contamination
        self.random_state = random_state
        self._model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
        )
        self._is_fitted = False

    def fit(self, matrix: FeatureMatrix) -> None:
        """Fit the underlying IsolationForest on a FeatureMatrix.

        Args:
            matrix: A FeatureMatrix whose rows are used exactly as
                given, in order.

        Raises:
            ValueError: If `matrix.rows` is empty.
        """
        if not matrix.rows:
            raise ValueError("Cannot fit AnomalyDetector on an empty FeatureMatrix.")

        self._model.fit(matrix.rows)
        self._is_fitted = True

    def score(self, matrix: FeatureMatrix) -> List[float]:
        """Return sklearn's decision_function score for each row.

        Args:
            matrix: A FeatureMatrix to score.

        Returns:
            One float per row in `matrix.rows`, in the same order.
            This is sklearn's raw decision_function output, not a
            probability.

        Raises:
            RuntimeError: If called before fit().
        """
        self._require_fitted()
        return [float(value) for value in self._model.decision_function(matrix.rows)]

    def predict(self, matrix: FeatureMatrix) -> List[int]:
        """Return sklearn's inlier/outlier prediction for each row.

        Args:
            matrix: A FeatureMatrix to classify.

        Returns:
            One int per row in `matrix.rows`, in the same order:
            1 for an inlier (normal), -1 for an outlier (anomaly).
            Never relabeled as "attack" or "benign".

        Raises:
            RuntimeError: If called before fit().
        """
        self._require_fitted()
        return [int(value) for value in self._model.predict(matrix.rows)]

    def _require_fitted(self) -> None:
        """Raise RuntimeError if fit() has not been called yet."""
        if not self._is_fitted:
            raise RuntimeError(
                "AnomalyDetector must be fitted with fit() before calling "
                "score() or predict()."
            )