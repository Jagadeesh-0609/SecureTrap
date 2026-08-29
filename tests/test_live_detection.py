"""Isolated unit tests for LiveDetectionPipeline.

Uses simple fake collaborators throughout — no real Cowrie, no
Docker, no network, no actual log files, and no sklearn. Fakes are
used specifically so orchestration (who gets called, in what order,
with what) can be verified without depending on real model behavior.
"""

import pytest

from core.ai_engine.anomaly_result import AnomalyResult
from core.dataset_manager.builder import DatasetRecord
from core.event_engine.event import AttackEvent
from core.event_engine.validator import ValidationResult
from core.log_processor.enricher import EnrichedEvent
from core.log_processor.processor import ProcessedEvent
from core.runtime.live_detection import LiveDetectionPipeline


def _make_attack_event(command: str = "pwd", event_type: str = "cowrie.command.input") -> AttackEvent:
    return AttackEvent(
        timestamp="2026-08-19T18:00:22.557428Z",
        source_ip="127.0.0.1",
        session_id="ce82815367a4",
        protocol="ssh",
        command=command,
        event_type=event_type,
        honeypot="Cowrie",
    )


def _valid_result(command: str = "pwd") -> ValidationResult:
    return ValidationResult(valid=True, event=_make_attack_event(command=command), errors=[])


def _invalid_result() -> ValidationResult:
    return ValidationResult(valid=False, event=None, errors=["bad data"])


class _FakeLogProcessor:
    """Fake LogProcessor that records events and returns a plain ProcessedEvent."""

    def __init__(self):
        self.processed_events = []

    def process(self, event):
        self.processed_events.append(event)
        return ProcessedEvent(
            original_event=event,
            event_type=event.event_type,
            normalized_command=event.command.strip(),
            category="command_execution",
            severity="low",
        )


class _FakeEventEnricher:
    """Fake EventEnricher that records inputs and returns a plain EnrichedEvent."""

    def __init__(self):
        self.enriched_events = []

    def enrich(self, processed_event):
        self.enriched_events.append(processed_event)
        command = processed_event.normalized_command
        return EnrichedEvent(
            processed_event=processed_event,
            has_command=bool(command),
            command_length=len(command),
            has_url=False,
            has_ip_address=False,
            has_file_path=False,
            has_shell_metacharacters=False,
        )


class _FakeDatasetBuilder:
    """Fake DatasetBuilder that records inputs and returns a DatasetRecord."""

    def __init__(self):
        self.built_events = []
        self.returned_records = []

    def build(self, enriched_event):
        self.built_events.append(enriched_event)
        original_event = enriched_event.processed_event.original_event
        record = DatasetRecord(
            timestamp=original_event.timestamp,
            source_ip=original_event.source_ip,
            session_id=original_event.session_id,
            protocol=original_event.protocol,
            honeypot=original_event.honeypot,
            event_type=enriched_event.processed_event.event_type,
            category=enriched_event.processed_event.category,
            severity=enriched_event.processed_event.severity,
            command=enriched_event.processed_event.normalized_command,
            has_command=enriched_event.has_command,
            command_length=enriched_event.command_length,
            has_url=enriched_event.has_url,
            has_ip_address=enriched_event.has_ip_address,
            has_file_path=enriched_event.has_file_path,
            has_shell_metacharacters=enriched_event.has_shell_metacharacters,
        )
        self.returned_records.append(record)
        return record


class _FakeModelManager:
    """Fake ModelManager: records fit()/predict() calls, never trains implicitly.

    `outputs` is a list of (prediction, score) tuples, consumed one
    per predict() call (predict() is always called with a single
    record by LiveDetectionPipeline).
    """

    def __init__(self, outputs=None, is_fitted: bool = True):
        self.fit_calls = []
        self.predict_calls = []
        self._is_fitted = is_fitted
        self._outputs = list(outputs) if outputs is not None else []
        self._call_index = 0

    def fit(self, records):
        self.fit_calls.append(list(records))

    def predict(self, records):
        record_list = list(records)
        self.predict_calls.append(record_list)

        if not self._is_fitted:
            raise RuntimeError(
                "ModelManager must be fitted with fit() before calling predict()."
            )

        prediction, score = self._outputs[self._call_index]
        self._call_index += 1

        return [
            AnomalyResult(
                record=record,
                prediction=prediction,
                score=score,
                is_anomaly=(prediction == -1),
            )
            for record in record_list
        ]


def test_valid_validation_result_produces_one_anomaly_result():
    pipeline = LiveDetectionPipeline(
        log_processor=_FakeLogProcessor(),
        event_enricher=_FakeEventEnricher(),
        dataset_builder=_FakeDatasetBuilder(),
        model_manager=_FakeModelManager(outputs=[(1, 0.1)]),
    )

    results = list(pipeline.process([_valid_result()]))

    assert len(results) == 1
    assert isinstance(results[0], AnomalyResult)


def test_invalid_validation_result_is_skipped():
    pipeline = LiveDetectionPipeline(
        log_processor=_FakeLogProcessor(),
        event_enricher=_FakeEventEnricher(),
        dataset_builder=_FakeDatasetBuilder(),
        model_manager=_FakeModelManager(outputs=[]),
    )

    results = list(pipeline.process([_invalid_result()]))

    assert results == []


def test_multiple_valid_events_preserve_order():
    events = [_valid_result(command="a"), _valid_result(command="b"), _valid_result(command="c")]
    pipeline = LiveDetectionPipeline(
        log_processor=_FakeLogProcessor(),
        event_enricher=_FakeEventEnricher(),
        dataset_builder=_FakeDatasetBuilder(),
        model_manager=_FakeModelManager(outputs=[(1, 0.1), (-1, -0.2), (1, 0.3)]),
    )

    results = list(pipeline.process(events))

    assert [result.record.command for result in results] == ["a", "b", "c"]


def test_log_processor_is_actually_used():
    fake_log_processor = _FakeLogProcessor()
    pipeline = LiveDetectionPipeline(
        log_processor=fake_log_processor,
        event_enricher=_FakeEventEnricher(),
        dataset_builder=_FakeDatasetBuilder(),
        model_manager=_FakeModelManager(outputs=[(1, 0.1)]),
    )
    validation_result = _valid_result(command="pwd")

    list(pipeline.process([validation_result]))

    assert fake_log_processor.processed_events == [validation_result.event]


def test_event_enricher_is_actually_used():
    fake_enricher = _FakeEventEnricher()
    pipeline = LiveDetectionPipeline(
        log_processor=_FakeLogProcessor(),
        event_enricher=fake_enricher,
        dataset_builder=_FakeDatasetBuilder(),
        model_manager=_FakeModelManager(outputs=[(1, 0.1)]),
    )

    list(pipeline.process([_valid_result(command="pwd")]))

    assert len(fake_enricher.enriched_events) == 1


def test_dataset_builder_is_actually_used():
    fake_builder = _FakeDatasetBuilder()
    pipeline = LiveDetectionPipeline(
        log_processor=_FakeLogProcessor(),
        event_enricher=_FakeEventEnricher(),
        dataset_builder=fake_builder,
        model_manager=_FakeModelManager(outputs=[(1, 0.1)]),
    )

    list(pipeline.process([_valid_result(command="pwd")]))

    assert len(fake_builder.built_events) == 1


def test_model_manager_predict_is_actually_used():
    fake_model_manager = _FakeModelManager(outputs=[(1, 0.1)])
    pipeline = LiveDetectionPipeline(
        log_processor=_FakeLogProcessor(),
        event_enricher=_FakeEventEnricher(),
        dataset_builder=_FakeDatasetBuilder(),
        model_manager=fake_model_manager,
    )

    list(pipeline.process([_valid_result(command="pwd")]))

    assert len(fake_model_manager.predict_calls) == 1


def test_model_manager_fit_is_never_called():
    fake_model_manager = _FakeModelManager(outputs=[(1, 0.1), (-1, -0.2)])
    pipeline = LiveDetectionPipeline(
        log_processor=_FakeLogProcessor(),
        event_enricher=_FakeEventEnricher(),
        dataset_builder=_FakeDatasetBuilder(),
        model_manager=fake_model_manager,
    )

    list(pipeline.process([_valid_result(command="a"), _valid_result(command="b")]))

    assert fake_model_manager.fit_calls == []


def test_a_single_event_is_handled_correctly():
    pipeline = LiveDetectionPipeline(
        log_processor=_FakeLogProcessor(),
        event_enricher=_FakeEventEnricher(),
        dataset_builder=_FakeDatasetBuilder(),
        model_manager=_FakeModelManager(outputs=[(-1, -0.5)]),
    )

    results = list(pipeline.process([_valid_result(command="pwd")]))

    assert len(results) == 1
    assert results[0].prediction == -1
    assert results[0].score == -0.5


def test_multiple_events_are_handled_correctly():
    events = [_valid_result(command="a"), _valid_result(command="b")]
    pipeline = LiveDetectionPipeline(
        log_processor=_FakeLogProcessor(),
        event_enricher=_FakeEventEnricher(),
        dataset_builder=_FakeDatasetBuilder(),
        model_manager=_FakeModelManager(outputs=[(1, 0.1), (-1, -0.2)]),
    )

    results = list(pipeline.process(events))

    assert len(results) == 2
    assert results[0].prediction == 1
    assert results[1].prediction == -1


def test_original_dataset_record_is_preserved_in_anomaly_result():
    fake_builder = _FakeDatasetBuilder()
    pipeline = LiveDetectionPipeline(
        log_processor=_FakeLogProcessor(),
        event_enricher=_FakeEventEnricher(),
        dataset_builder=fake_builder,
        model_manager=_FakeModelManager(outputs=[(1, 0.1)]),
    )

    results = list(pipeline.process([_valid_result(command="pwd")]))

    assert results[0].record is fake_builder.returned_records[0]


def test_model_manager_pre_fit_runtime_error_propagates():
    pipeline = LiveDetectionPipeline(
        log_processor=_FakeLogProcessor(),
        event_enricher=_FakeEventEnricher(),
        dataset_builder=_FakeDatasetBuilder(),
        model_manager=_FakeModelManager(outputs=[], is_fitted=False),
    )

    with pytest.raises(RuntimeError):
        list(pipeline.process([_valid_result(command="pwd")]))


def test_invalid_events_do_not_reach_downstream_components():
    fake_log_processor = _FakeLogProcessor()
    fake_enricher = _FakeEventEnricher()
    fake_builder = _FakeDatasetBuilder()
    fake_model_manager = _FakeModelManager(outputs=[])
    pipeline = LiveDetectionPipeline(
        log_processor=fake_log_processor,
        event_enricher=fake_enricher,
        dataset_builder=fake_builder,
        model_manager=fake_model_manager,
    )

    list(pipeline.process([_invalid_result()]))

    assert fake_log_processor.processed_events == []
    assert fake_enricher.enriched_events == []
    assert fake_builder.built_events == []
    assert fake_model_manager.predict_calls == []


def test_input_processing_does_not_modify_source_event_objects():
    validation_result = _valid_result(command="pwd")
    original_command = validation_result.event.command
    original_event_type = validation_result.event.event_type
    pipeline = LiveDetectionPipeline(
        log_processor=_FakeLogProcessor(),
        event_enricher=_FakeEventEnricher(),
        dataset_builder=_FakeDatasetBuilder(),
        model_manager=_FakeModelManager(outputs=[(1, 0.1)]),
    )

    list(pipeline.process([validation_result]))

    assert validation_result.event.command == original_command
    assert validation_result.event.event_type == original_event_type


def test_dependency_injection_works_with_fakes():
    fake_log_processor = _FakeLogProcessor()
    fake_enricher = _FakeEventEnricher()
    fake_builder = _FakeDatasetBuilder()
    fake_model_manager = _FakeModelManager(outputs=[(-1, -0.9)])

    pipeline = LiveDetectionPipeline(
        log_processor=fake_log_processor,
        event_enricher=fake_enricher,
        dataset_builder=fake_builder,
        model_manager=fake_model_manager,
    )
    results = list(pipeline.process([_valid_result(command="pwd")]))

    assert len(fake_log_processor.processed_events) == 1
    assert len(fake_enricher.enriched_events) == 1
    assert len(fake_builder.built_events) == 1
    assert len(fake_model_manager.predict_calls) == 1
    assert results[0].prediction == -1