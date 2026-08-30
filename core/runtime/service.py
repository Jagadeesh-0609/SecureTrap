"""Runtime — SecureTrap Service for SecureTrap.

Coordinates the existing LiveDetectionPipeline, AlertDispatcher, and
AlertStore into one continuous monitoring loop: validation results in,
persisted alerts out. This is orchestration only — it implements no
parsing, validation, enrichment, feature extraction, model training,
scoring, or anomaly filtering of its own; all of that already belongs
to the components it coordinates.

This module deliberately does not construct or import
LiveJsonLogReader, CowrieAdapter, or IngestionPipeline — it receives
the validation-result iterable from the caller, keeping:

    LiveJsonLogReader -> IngestionPipeline

separate from:

    IngestionPipeline output -> SecureTrapService
"""

from typing import Iterable

from core.alert_engine.alert_store import AlertStore
from core.event_engine.validator import ValidationResult
from core.runtime.alert_dispatch import AlertDispatcher
from core.runtime.live_detection import LiveDetectionPipeline


class SecureTrapService:
    """Runs validation results through detection, dispatch, and storage.

    For each ValidationResult in the supplied iterable:
        LiveDetectionPipeline turns valid events into AnomalyResults
            (invalid events are skipped by LiveDetectionPipeline
            itself and never reach this class).
        AlertDispatcher filters those AnomalyResults down to
            anomalies only, converting each into an Alert.
        AlertStore.save() persists every Alert produced.

    Processes the entire supplied iterable to exhaustion — suitable
    for a live iterable that normally runs indefinitely. Never calls
    ModelManager.fit(): the LiveDetectionPipeline it's given must
    already wrap an already-fitted model, and if it doesn't, the
    existing RuntimeError from prediction is left to propagate
    unchanged.

    All three collaborators are constructor-injectable, so this
    service can be unit-tested with simple fakes instead of always
    exercising real detection, dispatch, or sqlite I/O.
    """

    def __init__(
        self,
        live_detection_pipeline: LiveDetectionPipeline,
        alert_dispatcher: AlertDispatcher,
        alert_store: AlertStore,
    ) -> None:
        """Create a SecureTrapService over existing, already-configured components.

        No defaults are provided: a default LiveDetectionPipeline would
        need an already-fitted ModelManager, which this service has no
        safe way to construct on its own. All three dependencies must
        be supplied explicitly by the caller.

        Args:
            live_detection_pipeline: A LiveDetectionPipeline-compatible
                object providing
                `process(validation_results) -> Iterator[AnomalyResult]`,
                already wrapping an already-fitted model.
            alert_dispatcher: An AlertDispatcher-compatible object
                providing `dispatch(results) -> Iterator[Alert]`.
            alert_store: An AlertStore-compatible object providing
                `save(alert) -> int`.
        """
        self._live_detection_pipeline = live_detection_pipeline
        self._alert_dispatcher = alert_dispatcher
        self._alert_store = alert_store

    def run(self, validation_results: Iterable[ValidationResult]) -> int:
        """Process a stream of ValidationResult objects to exhaustion.

        Args:
            validation_results: The output of an IngestionPipeline —
                one ValidationResult per raw event, in order. Any
                iterable is accepted, including one that runs
                indefinitely; it is consumed exactly once, to
                exhaustion.

        Returns:
            The number of Alerts successfully persisted via
            AlertStore.save(). 0 for empty input.

        Raises:
            Whatever the underlying components raise — most notably,
            a RuntimeError from LiveDetectionPipeline/ModelManager if
            the model was never fitted. Such errors are not caught
            here; they propagate to the caller.
        """
        anomaly_results = self._live_detection_pipeline.process(validation_results)
        alerts = self._alert_dispatcher.dispatch(anomaly_results)

        persisted_count = 0
        for alert in alerts:
            self._alert_store.save(alert)
            persisted_count += 1

        return persisted_count