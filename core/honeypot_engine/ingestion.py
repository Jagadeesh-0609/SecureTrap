"""Ingestion / orchestration layer for SecureTrap.

Coordinates the existing Reader -> Adapter -> Validator components
into one reusable interface, so future SecureTrap modules don't have
to manually wire a reader, an adapter, and validate_event() together
themselves.

This module owns no parsing, no honeypot-specific knowledge, and no
validation rules of its own — it only orchestrates components that
already implement those responsibilities (JsonLogReader /
LiveJsonLogReader for reading, a BaseAdapter subclass for conversion,
validate_event() for validation).
"""

from dataclasses import asdict
from typing import Any, Iterable, Iterator

from core.event_engine.validator import ValidationResult, validate_event
from core.honeypot_engine.base_adapter import BaseAdapter


class IngestionPipeline:
    """Runs raw events from a reader through an adapter and the validator.

    Works with any reader that yields raw event dictionaries (e.g.
    JsonLogReader.read_events(), LiveJsonLogReader.follow(), or a
    plain list/generator in tests) and any BaseAdapter implementation
    (e.g. CowrieAdapter, or a future DionaeaAdapter). Neither a
    specific reader type nor a specific adapter type is referenced
    anywhere in this class.
    """

    def __init__(self, reader: Iterable[dict[str, Any]], adapter: BaseAdapter) -> None:
        """Create a pipeline over the given reader and adapter.

        Args:
            reader: Any iterable of raw event dictionaries.
            adapter: A BaseAdapter implementation that converts raw
                dictionaries into AttackEvent objects.
        """
        self._reader = reader
        self._adapter = adapter

    def process(self) -> Iterator[ValidationResult]:
        """Adapt and validate every raw event the reader produces.

        For each raw event: convert it with the adapter, then validate
        the result with validate_event(). If the adapter itself raises
        while converting a raw event (e.g. a required field is
        missing), that single event becomes a failed ValidationResult
        instead of stopping the whole stream — the exception's message
        is preserved as an error rather than discarded.

        Yields:
            One ValidationResult per raw event produced by the reader.
        """
        for raw_event in self._reader:
            yield self._process_one(raw_event)

    def _process_one(self, raw_event: dict[str, Any]) -> ValidationResult:
        """Adapt and validate a single raw event, isolating adapter failures."""
        try:
            attack_event = self._adapter.parse_event(raw_event)
        except Exception as exc:  # noqa: BLE001 - intentional: any adapter
            # failure becomes a reported result, not a crashed pipeline.
            return ValidationResult(
                valid=False,
                event=None,
                errors=[f"Adapter failed to parse raw event: {exc}"],
            )

        return validate_event(asdict(attack_event))