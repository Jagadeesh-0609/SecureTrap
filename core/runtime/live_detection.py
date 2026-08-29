"""Runtime — Live Detection Pipeline for SecureTrap.

Connects the output of the existing IngestionPipeline (a stream of
ValidationResult objects) to an already-fitted ModelManager, so live
events can be scored for anomalies without retraining the model.

This is orchestration only. It reuses LogProcessor, EventEnricher,
DatasetBuilder, and ModelManager exactly as they already exist — it
performs no parsing, validation, categorization, enrichment, feature
extraction, model training, scoring, or result mapping of its own.

This module deliberately does not construct or depend on
LiveJsonLogReader, CowrieAdapter, or IngestionPipeline directly — it
only consumes IngestionPipeline's output type (ValidationResult), so
it can be tested and reused without a real Cowrie process.
"""

from typing import Iterable, Iterator

from core.ai_engine.anomaly_result import AnomalyResult
from core.ai_engine.model_manager import ModelManager
from core.dataset_manager.builder import DatasetBuilder
from core.event_engine.validator import ValidationResult
from core.log_processor.enricher import EventEnricher
from core.log_processor.processor import LogProcessor


class LiveDetectionPipeline:
    """Turns valid live events into AnomalyResults via existing components.

    For each valid ValidationResult: its event is run through
    LogProcessor, then EventEnricher, then DatasetBuilder, and the
    resulting DatasetRecord is handed to an already-fitted
    ModelManager for prediction — yielding one AnomalyResult per valid
    input event, in order.

    Invalid ValidationResult objects (from upstream validation) are
    skipped entirely — they never reach LogProcessor and never
    produce an AnomalyResult. This class never calls
    ModelManager.fit(): the model must already be fitted before live
    processing starts, and if it isn't, ModelManager.predict()'s
    existing RuntimeError is allowed to propagate unchanged.
    """

    def __init__(
        self,
        log_processor: LogProcessor,
        event_enricher: EventEnricher,
        dataset_builder: DatasetBuilder,
        model_manager: ModelManager,
    ) -> None:
        """Create a LiveDetectionPipeline over existing, already-configured components.

        Args:
            log_processor: A LogProcessor-compatible object providing
                `process(attack_event) -> ProcessedEvent`.
            event_enricher: An EventEnricher-compatible object
                providing `enrich(processed_event) -> EnrichedEvent`.
            dataset_builder: A DatasetBuilder-compatible object
                providing `build(enriched_event) -> DatasetRecord`.
            model_manager: An already-fitted ModelManager-compatible
                object providing
                `predict(records) -> list[AnomalyResult]`. This
                pipeline never calls its `fit()`.
        """
        self._log_processor = log_processor
        self._event_enricher = event_enricher
        self._dataset_builder = dataset_builder
        self._model_manager = model_manager

    def process(self, validation_results: Iterable[ValidationResult]) -> Iterator[AnomalyResult]:
        """Process a stream of ValidationResult objects into AnomalyResults.

        Args:
            validation_results: The output of an IngestionPipeline —
                one ValidationResult per raw event, in order. Any
                iterable is accepted; it is consumed exactly once.

        Yields:
            One AnomalyResult per valid ValidationResult, in the same
            order they arrived. Invalid ValidationResult objects
            produce nothing and never reach any downstream component.
        """
        for validation_result in validation_results:
            if not validation_result.valid:
                continue

            attack_event = validation_result.event
            processed_event = self._log_processor.process(attack_event)
            enriched_event = self._event_enricher.enrich(processed_event)
            dataset_record = self._dataset_builder.build(enriched_event)

            anomaly_results = self._model_manager.predict([dataset_record])
            yield anomaly_results[0]