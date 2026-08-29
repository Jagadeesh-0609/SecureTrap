"""Stage 3 Log Processor for SecureTrap.

Converts already-validated AttackEvent objects into a standardized
ProcessedEvent representation, adding processing-level metadata
(category, severity, a normalized command) without discarding the
original event.

This module consumes SecureTrap's internal validated event
representation only. It does not read logs, does not know about any
specific honeypot's raw field names, and does not perform schema
validation — that already happened upstream (Ingestion -> validator).
Classification here is deterministic and keyword-based; no machine
learning is used at this stage.
"""

from dataclasses import dataclass

from core.event_engine.event import AttackEvent


@dataclass
class ProcessedEvent:
    """Standardized processed representation of a validated AttackEvent.

    Attributes:
        original_event: The original, validated AttackEvent this was
            derived from. Never discarded, never overwritten — its
            timestamp, source_ip, session_id, protocol, command,
            event_type, and honeypot fields all remain accessible to
            future processing stages.
        event_type: Copy of original_event.event_type, exposed
            directly for convenience.
        normalized_command: original_event.command with leading/
            trailing whitespace stripped. Otherwise left exactly as
            the attacker sent it — never rewritten, corrected, or
            reinterpreted.
        category: A small, extensible category label derived from
            event_type. One of: "session", "authentication",
            "command_execution", "session_termination",
            "client_activity", "file_transfer", "logging", or
            "other".
        severity: A conservative, deterministic severity label
            derived from event_type ("low" or "medium"). This is
            initial event-level metadata only, not a complete threat
            severity model.
    """

    original_event: AttackEvent
    event_type: str
    normalized_command: str
    category: str
    severity: str


class LogProcessor:
    """Converts validated AttackEvent objects into ProcessedEvent objects.

    Categorization and severity are derived from keywords present in
    the event_type string itself, rather than from a fixed list of
    Cowrie event names — so events produced by any honeypot adapter
    that follows the AttackEvent contract are handled the same way.
    """

    def process(self, event: AttackEvent) -> ProcessedEvent:
        """Convert one validated AttackEvent into a ProcessedEvent.

        Args:
            event: A validated AttackEvent (e.g. the `.event` from a
                successful ValidationResult).

        Returns:
            A ProcessedEvent preserving the original event alongside
            its category, severity, and normalized command.
        """
        return ProcessedEvent(
            original_event=event,
            event_type=event.event_type,
            normalized_command=event.command.strip(),
            category=self._categorize(event.event_type),
            severity=self._classify_severity(event.event_type),
        )

    @staticmethod
    def _categorize(event_type: str) -> str:
        """Derive a category from event_type using honeypot-agnostic keywords."""
        lowered = event_type.lower()

        if "file_download" in lowered:
            return "file_transfer"
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
        if "log" in lowered and "closed" in lowered:
            return "logging"
        return "other"

    @staticmethod
    def _classify_severity(event_type: str) -> str:
        """Derive a conservative severity label from event_type.

        Any event type indicating a failure is treated as "medium";
        everything else is "low". Intentionally simple and
        deterministic — this is only initial processing metadata.
        """
        return "medium" if "failed" in event_type.lower() else "low"