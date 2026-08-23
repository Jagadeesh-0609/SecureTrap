"""Stage 4 Dataset Manager for SecureTrap.

Orchestrates the existing DatasetBuilder and DatasetWriter to turn an
iterable of EnrichedEvent objects into persisted CSV dataset rows.
This class coordinates only — it duplicates no field-copying logic
from DatasetBuilder and no CSV logic from DatasetWriter.

This module operates entirely on SecureTrap's internal event
representation (EnrichedEvent). It does not read logs, parse JSON, or
know about any honeypot's raw fields.
"""

from pathlib import Path
from typing import Iterable, Optional, Union

from core.dataset_manager.builder import DatasetBuilder
from core.dataset_manager.writer import DatasetWriter
from core.log_processor.enricher import EnrichedEvent


class DatasetManager:
    """Coordinates DatasetBuilder and DatasetWriter for dataset generation.

    Accepts any iterable of EnrichedEvent objects (list, tuple,
    generator, etc.), builds one DatasetRecord per event via
    DatasetBuilder — preserving input order — and persists all
    records in a single call to DatasetWriter.

    DatasetBuilder and DatasetWriter are constructor-injectable, with
    sensible defaults, so DatasetManager can be unit-tested with
    simple fakes instead of always exercising real filesystem I/O.
    """

    def __init__(
        self,
        builder: Optional[DatasetBuilder] = None,
        writer: Optional[DatasetWriter] = None,
    ) -> None:
        """Create a DatasetManager, optionally overriding its collaborators.

        Args:
            builder: An object providing
                `build(enriched_event) -> DatasetRecord`. Defaults to
                a plain DatasetBuilder().
            writer: An object providing `write(records, path)`.
                Defaults to a plain DatasetWriter().
        """
        self._builder = builder if builder is not None else DatasetBuilder()
        self._writer = writer if writer is not None else DatasetWriter()

    def write_events(self, events: Iterable[EnrichedEvent], path: Union[str, Path]) -> None:
        """Build and persist DatasetRecord objects for the given events.

        Args:
            events: EnrichedEvent objects, in the order they should
                appear in the dataset. Any iterable is accepted
                (list, tuple, generator, etc.); it is consumed exactly
                once.
            path: Destination CSV path, passed through to the writer
                unchanged.
        """
        records = [self._builder.build(event) for event in events]
        self._writer.write(records, path)