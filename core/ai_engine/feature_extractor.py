"""AI Engine — Feature Extractor for SecureTrap.

Converts a DatasetRecord into a small, deterministic FeatureVector of
numeric/boolean features suitable for future machine-learning models.
This is feature extraction only — no model training, no persistence,
no prediction, no encoding of identifiers or categorical strings.

This module consumes DatasetRecord only. It does not read logs, call
any reader/adapter/ingestion/log-processing component, and does not
know about any honeypot's raw fields.
"""

from dataclasses import dataclass

from core.dataset_manager.builder import DatasetRecord


@dataclass
class FeatureVector:
    """A small, deterministic numeric representation of one DatasetRecord.

    Only fields that are already numeric or boolean on DatasetRecord
    are included here. Booleans are converted to 0/1. Identifiers
    (timestamp, source_ip, session_id) and categorical strings
    (honeypot, event_type, category, severity) are deliberately
    excluded — encoding those requires an explicit strategy that is
    out of scope for this first version.

    Attributes:
        command_length: Copied directly from DatasetRecord.
        has_command: 1 if DatasetRecord.has_command was True, else 0.
        has_url: 1 if DatasetRecord.has_url was True, else 0.
        has_ip_address: 1 if DatasetRecord.has_ip_address was True,
            else 0.
        has_file_path: 1 if DatasetRecord.has_file_path was True,
            else 0.
        has_shell_metacharacters: 1 if
            DatasetRecord.has_shell_metacharacters was True, else 0.
    """

    command_length: int
    has_command: int
    has_url: int
    has_ip_address: int
    has_file_path: int
    has_shell_metacharacters: int


class FeatureExtractor:
    """Extracts a deterministic FeatureVector from a DatasetRecord.

    Purely a field-copying / boolean-to-integer conversion: no model
    training, no scaling, no randomness, no external state. The same
    DatasetRecord always produces the same FeatureVector, and the
    input record is never modified.
    """

    def extract(self, record: DatasetRecord) -> FeatureVector:
        """Convert one DatasetRecord into a FeatureVector.

        Args:
            record: A DatasetRecord produced by DatasetBuilder.

        Returns:
            A FeatureVector containing only the numeric/boolean
            features already present on the record, with booleans
            converted to 0/1.
        """
        return FeatureVector(
            command_length=record.command_length,
            has_command=int(record.has_command),
            has_url=int(record.has_url),
            has_ip_address=int(record.has_ip_address),
            has_file_path=int(record.has_file_path),
            has_shell_metacharacters=int(record.has_shell_metacharacters),
        )