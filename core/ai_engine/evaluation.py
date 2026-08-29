"""AI Engine — Evaluation for SecureTrap.

Summarizes observable model behavior across a batch of AnomalyResult
objects: counts, anomaly rate, and score statistics. This reports
only what IsolationForest actually produced — it never calculates or
implies supervised-learning metrics (accuracy, precision, recall, F1,
AUC) since there is no verified ground-truth label set to compute
them against, and it never introduces an attack/benign judgment.

This module consumes AnomalyResult only. It does not rerun the model,
reconstruct a FeatureMatrix, read logs/CSV, or call sklearn.
"""

from dataclasses import dataclass
from typing import Iterable, List, Optional

from core.ai_engine.anomaly_result import AnomalyResult


@dataclass
class EvaluationReport:
    """A deterministic summary of a batch of AnomalyResult objects.

    Attributes:
        total_count: Number of results evaluated.
        normal_count: Number of results with is_anomaly == False.
        anomaly_count: Number of results with is_anomaly == True.
        anomaly_rate: anomaly_count / total_count, or 0.0 when
            total_count is 0.
        min_score: The minimum result.score across the batch, or None
            for empty input.
        max_score: The maximum result.score across the batch, or None
            for empty input.
        mean_score: The arithmetic mean of result.score across the
            batch, or None for empty input.
    """

    total_count: int
    normal_count: int
    anomaly_count: int
    anomaly_rate: float
    min_score: Optional[float]
    max_score: Optional[float]
    mean_score: Optional[float]


class AnomalyEvaluator:
    """Builds an EvaluationReport from a batch of AnomalyResult objects.

    Purely an aggregation over values already present on each
    AnomalyResult: no model calls, no feature extraction, no I/O.
    Deterministic — the same results always produce the same report,
    and the input results (and their DatasetRecords) are never
    modified.
    """

    def evaluate(self, results: Iterable[AnomalyResult]) -> EvaluationReport:
        """Summarize a batch of AnomalyResult objects.

        Args:
            results: AnomalyResult objects to summarize. Any iterable
                is accepted (list, tuple, generator, etc.); it is
                consumed exactly once. Order does not affect the
                report.

        Returns:
            An EvaluationReport. For empty input, all counts are 0,
            anomaly_rate is 0.0, and the score fields are None.
        """
        result_list: List[AnomalyResult] = list(results)
        total_count = len(result_list)

        if total_count == 0:
            return EvaluationReport(
                total_count=0,
                normal_count=0,
                anomaly_count=0,
                anomaly_rate=0.0,
                min_score=None,
                max_score=None,
                mean_score=None,
            )

        anomaly_count = sum(1 for result in result_list if result.is_anomaly)
        normal_count = total_count - anomaly_count
        scores = [result.score for result in result_list]

        return EvaluationReport(
            total_count=total_count,
            normal_count=normal_count,
            anomaly_count=anomaly_count,
            anomaly_rate=anomaly_count / total_count,
            min_score=min(scores),
            max_score=max(scores),
            mean_score=sum(scores) / total_count,
        )