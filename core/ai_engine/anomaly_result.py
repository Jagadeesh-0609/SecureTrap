"""AI Engine — Anomaly Result for SecureTrap.

Connects a DatasetRecord to the IsolationForest prediction and score
already produced by AnomalyDetector, so a model's output can be traced
back to the exact dataset row that produced it.

This module is a pure result/mapping layer. It does not call sklearn,
does not perform feature extraction, does not read logs or files, and
never invents a security classification (no attack/benign label,
probability, confidence, or threat level) — it only represents
IsolationForest's own inlier/outlier output.

This module depends on DatasetRecord, but never the reverse, and never
on AnomalyDetector, FeatureExtractor, or FeatureMatrixBuilder.
"""

from dataclasses import dataclass

from core.dataset_manager.builder import DatasetRecord

_VALID_PREDICTIONS = (1, -1)


@dataclass
class AnomalyResult:
    """One DatasetRecord paired with its IsolationForest output.

    Attributes:
        record: The original DatasetRecord this result was built
            from, preserved unchanged — the same object, not a copy.
        prediction: IsolationForest's raw prediction: 1 = inlier /
            normal, -1 = outlier / anomaly. Never relabeled.
        score: IsolationForest's decision_function score for this
            record, as produced by AnomalyDetector. Not a
            probability.
        is_anomaly: True exactly when prediction == -1, False exactly
            when prediction == 1. Always derived from `prediction`,
            never supplied independently, so the two can never
            disagree.
    """

    record: DatasetRecord
    prediction: int
    score: float
    is_anomaly: bool


class AnomalyResultBuilder:
    """Builds AnomalyResult objects from a record, prediction, and score.

    Purely a validation/mapping operation: no model calls, no feature
    extraction, no I/O. Deterministic — the same
    (record, prediction, score) always produces the same
    AnomalyResult, and the input record is never modified.
    """

    def build(self, record: DatasetRecord, prediction: int, score: float) -> AnomalyResult:
        """Build an AnomalyResult from a record and its model output.

        Args:
            record: The DatasetRecord this output corresponds to.
                Preserved unchanged and by identity.
            prediction: IsolationForest's raw prediction. Must be
                exactly 1 or -1.
            score: IsolationForest's decision_function score for this
                record. Stored as a float.

        Returns:
            An AnomalyResult with `is_anomaly` derived from
            `prediction` (True for -1, False for 1).

        Raises:
            ValueError: If `prediction` is not 1 or -1.
        """
        if prediction not in _VALID_PREDICTIONS:
            raise ValueError(
                f"Invalid IsolationForest prediction {prediction!r}: "
                f"expected one of {_VALID_PREDICTIONS!r}."
            )

        return AnomalyResult(
            record=record,
            prediction=prediction,
            score=float(score),
            is_anomaly=(prediction == -1),
        )