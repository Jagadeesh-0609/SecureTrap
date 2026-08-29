"""Runtime — Alert Dispatch for SecureTrap.

Filters a stream of AnomalyResult objects down to only the anomalous
ones and converts each into an Alert via the existing AlertBuilder.
Normal results (is_anomaly == False) never produce an Alert.

This is a filter/orchestration layer only — it reuses AlertBuilder's
existing field-copying logic and adds no notification delivery,
persistence, deduplication, or model calls of its own.

This module operates on AnomalyResult only. It has no dependency on
ModelManager, AnomalyDetector, FeatureMatrixBuilder, FeatureExtractor,
DatasetBuilder, or any honeypot/ingestion/log-processing component.
"""

from typing import Iterable, Iterator, Optional

from core.ai_engine.anomaly_result import AnomalyResult
from core.alert_engine.alert import Alert, AlertBuilder


class AlertDispatcher:
    """Converts only anomalous AnomalyResults into Alert objects.

    For every AnomalyResult: results with is_anomaly == False are
    skipped entirely; results with is_anomaly == True are passed to
    AlertBuilder.build() and the resulting Alert is yielded. Input
    order is preserved for the alerts that are produced.

    AlertBuilder is constructor-injectable, with a sensible default,
    so this dispatcher can be unit-tested with a fake builder.
    """

    def __init__(self, alert_builder: Optional[AlertBuilder] = None) -> None:
        """Create an AlertDispatcher, optionally overriding its AlertBuilder.

        Args:
            alert_builder: An object providing
                `build(result) -> Alert`. Defaults to a plain
                AlertBuilder().
        """
        self._alert_builder = alert_builder if alert_builder is not None else AlertBuilder()

    def dispatch(self, results: Iterable[AnomalyResult]) -> Iterator[Alert]:
        """Yield an Alert for each anomalous AnomalyResult, in order.

        Args:
            results: AnomalyResult objects, in order. Any iterable is
                accepted (list, tuple, generator, etc.); it is
                consumed exactly once.

        Yields:
            One Alert per AnomalyResult where `is_anomaly` is True, in
            the same relative order they arrived. Results where
            `is_anomaly` is False produce nothing and are never passed
            to AlertBuilder.
        """
        for result in results:
            if not result.is_anomaly:
                continue

            yield self._alert_builder.build(result)