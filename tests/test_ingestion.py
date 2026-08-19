"""Isolated unit tests for the SecureTrap ingestion pipeline.

Uses small fake readers and a fake BaseAdapter implementation so the
pipeline is proven generic — not dependent on Cowrie, JsonLogReader,
or LiveJsonLogReader. Requires no Cowrie, no Docker, no network, no
real log files, no database, and no other external services.
"""

from typing import Any, Mapping

from core.event_engine.event import AttackEvent
from core.event_engine.validator import ValidationResult
from core.honeypot_engine.base_adapter import BaseAdapter
from core.honeypot_engine.ingestion import IngestionPipeline

VALID_RAW_EVENT = {
    "timestamp": "2026-08-11T18:30:00",
    "source_ip": "192.168.1.10",
    "session_id": "session001",
    "protocol": "SSH",
    "command": "ls -la",
    "event_type": "command",
    "honeypot": "Cowrie",
}


class FakeAdapter(BaseAdapter):
    """A minimal, non-Cowrie adapter used only to prove the pipeline is generic."""

    def parse_event(self, raw_event: Mapping[str, Any]) -> AttackEvent:
        return AttackEvent(**raw_event)


def test_valid_raw_event_passes_through_adapter_and_validator():
    pipeline = IngestionPipeline([VALID_RAW_EVENT], FakeAdapter())

    results = list(pipeline.process())

    assert len(results) == 1
    assert isinstance(results[0], ValidationResult)


def test_multiple_raw_events_produce_multiple_results():
    raw_events = [VALID_RAW_EVENT, VALID_RAW_EVENT, VALID_RAW_EVENT]
    pipeline = IngestionPipeline(raw_events, FakeAdapter())

    results = list(pipeline.process())

    assert len(results) == 3


def test_valid_event_results_in_valid_true():
    pipeline = IngestionPipeline([VALID_RAW_EVENT], FakeAdapter())

    result = next(pipeline.process())

    assert result.valid is True
    assert result.event is not None
    assert result.errors == []


def test_invalid_normalized_event_results_in_valid_false():
    invalid_raw_event = {**VALID_RAW_EVENT, "source_ip": "not-an-ip"}
    pipeline = IngestionPipeline([invalid_raw_event], FakeAdapter())

    result = next(pipeline.process())

    assert result.valid is False
    assert result.event is None


def test_pipeline_works_with_a_generic_non_cowrie_reader():
    def custom_reader():
        yield VALID_RAW_EVENT

    pipeline = IngestionPipeline(custom_reader(), FakeAdapter())

    results = list(pipeline.process())

    assert len(results) == 1
    assert results[0].valid is True


def test_pipeline_works_with_a_generic_non_cowrie_adapter():
    pipeline = IngestionPipeline([VALID_RAW_EVENT], FakeAdapter())

    result = next(pipeline.process())

    assert result.valid is True


def test_reader_output_is_passed_to_the_adapter():
    seen_raw_events = []

    class RecordingAdapter(BaseAdapter):
        def parse_event(self, raw_event: Mapping[str, Any]) -> AttackEvent:
            seen_raw_events.append(raw_event)
            return AttackEvent(**raw_event)

    pipeline = IngestionPipeline([VALID_RAW_EVENT], RecordingAdapter())
    list(pipeline.process())

    assert seen_raw_events == [VALID_RAW_EVENT]


def test_adapter_output_is_passed_to_validate_event():
    # An adapter can produce a structurally invalid AttackEvent (e.g. a
    # bad IP straight from a raw log); validate_event() must be the
    # thing that catches it, proving the pipeline really calls it.
    bad_ip_event = {**VALID_RAW_EVENT, "source_ip": "999.999.999.999"}
    pipeline = IngestionPipeline([bad_ip_event], FakeAdapter())

    result = next(pipeline.process())

    assert result.valid is False
    assert any("source_ip" in error for error in result.errors)


def test_validation_errors_are_preserved():
    invalid_raw_event = {**VALID_RAW_EVENT, "session_id": "   "}
    pipeline = IngestionPipeline([invalid_raw_event], FakeAdapter())

    result = next(pipeline.process())

    assert result.valid is False
    assert len(result.errors) > 0


def test_empty_reader_produces_no_results():
    pipeline = IngestionPipeline([], FakeAdapter())

    results = list(pipeline.process())

    assert results == []


def test_adapter_exception_produces_invalid_result_without_crashing_pipeline():
    class FailingAdapter(BaseAdapter):
        def parse_event(self, raw_event: Mapping[str, Any]) -> AttackEvent:
            raise KeyError("missing_field")

    pipeline = IngestionPipeline([VALID_RAW_EVENT, VALID_RAW_EVENT], FailingAdapter())

    results = list(pipeline.process())

    assert len(results) == 2
    assert all(result.valid is False for result in results)
    assert all(result.event is None for result in results)
    assert all(len(result.errors) > 0 for result in results)