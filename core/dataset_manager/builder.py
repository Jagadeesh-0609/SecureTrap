"""Stage 4 Dataset Builder for SecureTrap.

Converts an already-enriched SecureTrap event (EnrichedEvent) into a
stable, flat DatasetRecord suitable for future tabular dataset
generation. This is dataset preparation only — no CSV writing, no
database storage, no labeling, no machine learning.

This module consumes SecureTrap's internal validated/processed/
enriched event representation only. It does not read logs, parse
JSON, or know about any honeypot's raw fields.
"""

from dataclasses import dataclass

from core.log_processor.enricher import EnrichedEvent


@dataclass
class DatasetRecord:
    """A flat, stable dataset row derived from one EnrichedEvent.

    Every field is copied directly from the underlying AttackEvent /
    ProcessedEvent / EnrichedEvent — nothing is computed, relabeled,
    or renormalized here. Deliberately excludes any attack label
    (e.g. "malware", "brute_force", "benign"): the current data has
    no verified ground-truth labels, so none are invented.

    Attributes:
        timestamp: From the original AttackEvent.
        source_ip: From the original AttackEvent.
        session_id: From the original AttackEvent.
        protocol: From the original AttackEvent.
        honeypot: From the original AttackEvent.
        event_type: From the ProcessedEvent.
        category: From the ProcessedEvent.
        severity: From the ProcessedEvent.
        command: The normalized command, copied exactly from
            ProcessedEvent.normalized_command — no further
            normalization is applied here.
        has_command: From the EnrichedEvent.
        command_length: From the EnrichedEvent.
        has_url: From the EnrichedEvent.
        has_ip_address: From the EnrichedEvent.
        has_file_path: From the EnrichedEvent.
        has_shell_metacharacters: From the EnrichedEvent.
    """

    timestamp: str
    source_ip: str
    session_id: str
    protocol: str
    honeypot: str
    event_type: str
    category: str
    severity: str
    command: str
    has_command: bool
    command_length: int
    has_url: bool
    has_ip_address: bool
    has_file_path: bool
    has_shell_metacharacters: bool


class DatasetBuilder:
    """Builds a flat DatasetRecord from an EnrichedEvent.

    Purely a field-copying operation: no labeling, no additional
    command normalization, no machine learning. Deterministic — the
    same EnrichedEvent always produces the same DatasetRecord, and the
    input is never modified.
    """

    def build(self, enriched_event: EnrichedEvent) -> DatasetRecord:
        """Convert one EnrichedEvent into a DatasetRecord.

        Args:
            enriched_event: An EnrichedEvent produced by EventEnricher.

        Returns:
            A DatasetRecord with every field copied directly from the
            underlying AttackEvent, ProcessedEvent, and EnrichedEvent.
        """
        processed_event = enriched_event.processed_event
        original_event = processed_event.original_event

        return DatasetRecord(
            timestamp=original_event.timestamp,
            source_ip=original_event.source_ip,
            session_id=original_event.session_id,
            protocol=original_event.protocol,
            honeypot=original_event.honeypot,
            event_type=processed_event.event_type,
            category=processed_event.category,
            severity=processed_event.severity,
            command=processed_event.normalized_command,
            has_command=enriched_event.has_command,
            command_length=enriched_event.command_length,
            has_url=enriched_event.has_url,
            has_ip_address=enriched_event.has_ip_address,
            has_file_path=enriched_event.has_file_path,
            has_shell_metacharacters=enriched_event.has_shell_metacharacters,
        )