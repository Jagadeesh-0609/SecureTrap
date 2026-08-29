"""AI Engine — Inference Orchestration for SecureTrap.

Provides one reusable interface (AIInferenceEngine) that coordinates
the existing AI components — FeatureMatrixBuilder, AnomalyDetector,
and AnomalyResultBuilder — so callers can go directly from
DatasetRecord objects to AnomalyResult objects without manually
wiring the pipeline together.

This module reuses each collaborator's existing logic and duplicates
none of it: no feature extraction, no matrix construction, no
IsolationForest logic, and no result-mapping logic of its own.

This module operates on DatasetRecord only. It does not read logs,
call any reader/adapter/ingestion/log-processing component, and does
not import DatasetBuilder or DatasetWriter.
"""

from typing import Iterable, List, Optional

from core.ai_engine.anomaly_detector import AnomalyDetector
from core.ai_engine.anomaly_result import AnomalyResult, AnomalyResultBuilder
from core.ai_engine.feature_matrix import FeatureMatrixBuilder
from core.dataset_manager.builder import DatasetRecord


class AIInferenceEngine:
    """Coordinates FeatureMatrixBuilder, AnomalyDetector, and AnomalyResultBuilder.

    Given an iterable of DatasetRecord objects, builds a FeatureMatrix,
    fits the AnomalyDetector on it, scores/predicts the same records,
    and pairs each original record with its prediction and score via
    AnomalyResultBuilder — preserving input order and record identity.

    All three collaborators are constructor-injectable, with sensible
    defaults, so this orchestration can be unit-tested with simple
    fakes instead of always exercising real feature extraction or
    sklearn.
    """

    def __init__(
        self,
        matrix_builder: Optional[FeatureMatrixBuilder] = None,
        detector: Optional[AnomalyDetector] = None,
        result_builder: Optional[AnomalyResultBuilder] = None,
    ) -> None:
        """Create an AIInferenceEngine, optionally overriding its collaborators.

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

    def analyze(self, records: Iterable[DatasetRecord]) -> List[AnomalyResult]:
        """Run the full DatasetRecord -> AnomalyResult pipeline.

        For this first version, the detector is fit on the supplied
        records and then used to score/predict those same records —
        no train/test split, persistence, or retraining policy.

        Args:
            records: DatasetRecord objects, in the order results
                should be returned. Any iterable is accepted; it is
                consumed exactly once.

        Returns:
            One AnomalyResult per input record, in the same order.
            Returns [] if `records` is empty — the detector is never
            fit on an empty matrix.
        """
        record_list: List[DatasetRecord] = list(records)

        if not record_list:
            return []

        matrix = self._matrix_builder.build(record_list)
        self._detector.fit(matrix)
        predictions = self._detector.predict(matrix)
        scores = self._detector.score(matrix)

        return [
            self._result_builder.build(record, prediction, score)
            for record, prediction, score in zip(record_list, predictions, scores)
        ]