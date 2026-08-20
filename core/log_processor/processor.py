"""Stage 3 Log Processor for SecureTrap.

Converts validated AttackEvent objects into a standardized
ProcessedEvent representation by adding deterministic processing
metadata while preserving the original event.
"""

from dataclasses import dataclass

from core.event_engine.event import AttackEvent


@dataclass
class ProcessedEvent:
    """Processed representation of a validated AttackEvent.

    Attributes:
        original_event: The original AttackEvent preserved unchanged.
        event_type: Original event type for convenient access.
        normalized_command: Command with surrounding whitespace removed.
        category: Deterministic event category.
        severity: Initial deterministic severity label.
    """

    original_event: AttackEvent
    event_type: str
    normalized_command: str
    category: str
    severity: str


class LogProcessor:
    """Convert validated AttackEvent objects into ProcessedEvent objects."""

    def process(self, event: AttackEvent) -> ProcessedEvent:
        """Process one validated AttackEvent."""
        return ProcessedEvent(
            original_event=event,
            event_type=event.event_type,
            normalized_command=event.command.strip(),
            category=self._categorize(event.event_type),
            severity=self._classify_severity(event.event_type),
        )

    @staticmethod
    def _categorize(event_type: str) -> str:
        """Classify an event using honeypot-independent event-type patterns."""
        lowered = event_type.lower()

        if "session" in lowered and "closed" in lowered:
            return "session_termination"

        if "session" in lowered:
            return "session"

        if "login" in lowered:
            return "authentication"

        if "command" in lowered:
            return "command_execution"

        if "client" in lowered:
            return "client_activity"

        return "other"

    @staticmethod
    def _classify_severity(event_type: str) -> str:
        """Assign the initial deterministic severity label."""
        return "medium" if "failed" in event_type.lower() else "low"