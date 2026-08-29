"""AI Engine — Model Manager for SecureTrap.

Separates model fitting (a baseline/training step) from inference (a
repeatable, non-retraining step), reusing the existing
FeatureMatrixBuilder, AnomalyDetector, and AnomalyResultBuilder.

fit() must be called once to establish a baseline; predict() may then
be called any number of times, on different DatasetRecord batches,
without ever retraining the underlying detector. This is the
correct lifecycle for later real-time detection: a baseline is
learned once, and new events are only ever scored against it.

This module operates on DatasetRecord and the existing AI components
only. It does not read logs, call any reader/adapter/ingestion/
log-processing component, and performs no model persistence.
"""

from typing import Iterable, List, Optional

from core.ai_engine.anomaly_detector import AnomalyDetector
from core.ai_engine.anomaly_result import AnomalyResult, AnomalyResultBuilder
from core.ai_engine.feature_matrix import FeatureMatrixBuilder
from core.dataset_manager.builder import DatasetRecord


class ModelManager:
    """Separates model fitting from inference for SecureTrap's AI Engine.

    fit() builds a baseline FeatureMatrix from training records and
    fits the injected AnomalyDetector on it exactly once. predict()
    may then be called repeatedly, on different DatasetRecord
    batches, and never calls detector.fit() itself — it only scores
    and predicts against the already-fitted model.

    FeatureMatrixBuilder, AnomalyDetector, and AnomalyResultBuilder
    are constructor-injectable, with sensible defaults, so this
    lifecycle can be unit-tested with simple fakes instead of always
    exercising real feature extraction or sklearn.
    """

    def __init__(
        self,
        matrix_builder: Optional[FeatureMatrixBuilder] = None,
        detector: Optional[AnomalyDetector] = None,
        result_builder: Optional[AnomalyResultBuilder] = None,
    ) -> None:
        """Create a ModelManager, optionally overriding its collaborators.

        Args:
            matrix_builder: An object providing
                `build(records) -> FeatureMatrix`. Defaults to a plain
                FeatureMatrixBuilder().
            detector: An object providing `fit(matrix)`,
                `predict(matrix) -> list[int]`, and
                `score(matrix) -> list[float]`. Defaults to a plain
                AnomalyDetector().
            result_builder: An object providing
                `build(record, prediction, score) -> AnomalyResult`.
                Defaults to a plain AnomalyResultBuilder().
        """
        self._matrix_builder = (
            matrix_builder if matrix_builder is not None else FeatureMatrixBuilder()
        )
        self._detector = detector if detector is not None else AnomalyDetector()
        self._result_builder = (
            result_builder if result_builder is not None else AnomalyResultBuilder()
        )
        self._is_fitted = False

    def fit(self, records: Iterable[DatasetRecord]) -> None:
        """Establish a baseline by fitting the detector on training records.

        Args:
            records: DatasetRecord objects to train on. Any iterable
                is accepted; it is consumed exactly once.

        Raises:
            ValueError: If `records` is empty.
        """
        record_list: List[DatasetRecord] = list(records)

        if not record_list:
            raise ValueError("Cannot fit ModelManager on an empty set of training records.")

        matrix = self._matrix_builder.build(record_list)
        self._detector.fit(matrix)
        self._is_fitted = True

    def predict(self, records: Iterable[DatasetRecord]) -> List[AnomalyResult]:
        """Score/predict new records against the already-fitted detector.

        Never retrains the detector: fit() must be called first, and
        every call to predict() reuses that same fitted model. The
        records passed here may be an entirely different batch than
        what fit() was trained on.

        Args:
            records: DatasetRecord objects to run inference on. Any
                iterable is accepted; it is consumed exactly once.

        Returns:
            One AnomalyResult per input record, in the same order.
            Returns [] if `records` is empty.

        Raises:
            RuntimeError: If called before fit() — including when
                `records` is also empty, since the model lifecycle has
                not been initialized yet.
        """
        if not self._is_fitted:
            raise RuntimeError(
                "ModelManager must be fitted with fit() before calling predict()."
            )

        record_list: List[DatasetRecord] = list(records)

        if not record_list:
            return []

        matrix = self._matrix_builder.build(record_list)
        predictions = self._detector.predict(matrix)
        scores = self._detector.score(matrix)

        return [
            self._result_builder.build(record, prediction, score)
            for record, prediction, score in zip(record_list, predictions, scores)
        ]