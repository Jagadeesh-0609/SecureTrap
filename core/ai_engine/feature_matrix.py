"""AI Engine — Feature Matrix for SecureTrap.

Combines multiple DatasetRecord objects into an ordered, deterministic
FeatureMatrix of numeric feature rows, reusing the existing
FeatureExtractor for every record. This is organization only — no
scaling, no encoding, no labeling, no model training.

This module consumes DatasetRecord only. It does not read logs, call
any reader/adapter/ingestion/log-processing component, and does not
know about any honeypot's raw fields.
"""

from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

from core.ai_engine.feature_extractor import FeatureExtractor, FeatureVector
from core.dataset_manager.builder import DatasetRecord

FEATURE_NAMES: Tuple[str, str, str, str, str, str] = (
    "command_length",
    "has_command",
    "has_url",
    "has_ip_address",
    "has_file_path",
    "has_shell_metacharacters",
)


@dataclass
class FeatureMatrix:
    """A deterministic, ordered collection of numeric feature rows.

    Attributes:
        feature_names: The fixed, ordered column names every row
            follows. Always equal to FEATURE_NAMES.
        rows: One tuple of ints per input DatasetRecord, in the same
            order as the input. Each tuple's values align
            position-for-position with feature_names.
    """

    feature_names: Tuple[str, ...]
    rows: List[Tuple[int, int, int, int, int, int]]


def _vector_to_row(vector: FeatureVector) -> Tuple[int, int, int, int, int, int]:
    """Convert a FeatureVector into a row tuple matching FEATURE_NAMES order."""
    return (
        vector.command_length,
        vector.has_command,
        vector.has_url,
        vector.has_ip_address,
        vector.has_file_path,
        vector.has_shell_metacharacters,
    )


class FeatureMatrixBuilder:
    """Builds a FeatureMatrix from an iterable of DatasetRecord objects.

    Reuses the existing FeatureExtractor for every record — this
    class only organizes already-extracted FeatureVectors into an
    ordered matrix; it recalculates or reinterprets nothing.

    FeatureExtractor is constructor-injectable, with a sensible
    default, mirroring the DatasetManager pattern.
    """

    def __init__(self, extractor: Optional[FeatureExtractor] = None) -> None:
        """Create a FeatureMatrixBuilder, optionally overriding the extractor.

        Args:
            extractor: An object providing
                `extract(record) -> FeatureVector`. Defaults to a
                plain FeatureExtractor().
        """
        self._extractor = extractor if extractor is not None else FeatureExtractor()

    def build(self, records: Iterable[DatasetRecord]) -> FeatureMatrix:
        """Build a FeatureMatrix from the given DatasetRecord objects.

        Args:
            records: DatasetRecord objects, in the order they should
                appear as matrix rows. Any iterable is accepted (list,
                tuple, generator, etc.); it is consumed exactly once.

        Returns:
            A FeatureMatrix whose rows are in the same order as
            `records`, with feature_names fixed to FEATURE_NAMES. An
            empty input produces an empty-rows matrix with the same
            fixed feature_names.
        """
        rows = [_vector_to_row(self._extractor.extract(record)) for record in records]
        return FeatureMatrix(feature_names=FEATURE_NAMES, rows=rows)