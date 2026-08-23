"""Stage 3 Session Aggregator for SecureTrap.

Combines the already processed/enriched events belonging to a single
honeypot session into a compact SessionSummary. This is aggregation
only — it derives simple counts and a time span from events that were
already categorized upstream (LogProcessor / EventEnricher); it makes
no threat judgment of its own.

This module operates entirely on SecureTrap's internal event
representation (EnrichedEvent -> ProcessedEvent -> AttackEvent). It
does not read logs, parse JSON, or know about any honeypot's raw
fields.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Tuple

from core.log_processor.enricher import EnrichedEvent


@dataclass
class SessionSummary:
    """Compact, session-level aggregation of a honeypot session's events.

    Attributes:
        session_id: The session identifier shared by all input events.
        source_ip: The source IP shared by all input events.
        protocol: The protocol shared by all input events.
        honeypot: The honeypot name shared by all input events.
        start_time: The earliest event timestamp in the session, as
            the original ISO-8601 string (unmodified).
        end_time: The latest event timestamp in the session, as the
            original ISO-8601 string (unmodified).
        event_count: Total number of events in the session.
        command_count: Number of events categorized as
            "command_execution".
        login_success_count: Number of authentication events whose
            event_type indicates a successful login.
        login_failure_count: Number of authentication events whose
            event_type indicates a failed login.
    """

    session_id: str
    source_ip: str
    protocol: str
    honeypot: str
    start_time: str
    end_time: str
    event_count: int
    command_count: int
    login_success_count: int
    login_failure_count: int


def _parse_timestamp(timestamp: str) -> datetime:
    """Parse an ISO-8601 timestamp, tolerating a trailing 'Z'."""
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


class SessionAggregator:
    """Aggregates a session's EnrichedEvent objects into a SessionSummary.

    All input events are expected to belong to the same session. This
    is enforced explicitly: an empty input, or inconsistent
    session_id, source_ip, protocol, or honeypot values across the
    input, raise ValueError rather than being silently accepted or
    merged.
    """

    def aggregate(self, events: Iterable[EnrichedEvent]) -> SessionSummary:
        """Aggregate one session's worth of EnrichedEvent objects.

        Args:
            events: EnrichedEvent objects, all expected to belong to
                the same session.

        Returns:
            A SessionSummary describing the session.

        Raises:
            ValueError: If `events` is empty, or if the events do not
                all share the same session_id, source_ip, protocol,
                and honeypot.
        """
        event_list: List[EnrichedEvent] = list(events)

        if not event_list:
            raise ValueError("Cannot aggregate an empty sequence of events.")

        session_id, source_ip, protocol, honeypot = self._resolve_identity(event_list)

        timestamps = [
            enriched.processed_event.original_event.timestamp for enriched in event_list
        ]
        start_time = min(timestamps, key=_parse_timestamp)
        end_time = max(timestamps, key=_parse_timestamp)

        command_count = sum(
            1
            for enriched in event_list
            if enriched.processed_event.category == "command_execution"
        )
        login_success_count = sum(
            1
            for enriched in event_list
            if enriched.processed_event.category == "authentication"
            and "login.success" in enriched.processed_event.event_type
        )
        login_failure_count = sum(
            1
            for enriched in event_list
            if enriched.processed_event.category == "authentication"
            and "login.failed" in enriched.processed_event.event_type
        )

        return SessionSummary(
            session_id=session_id,
            source_ip=source_ip,
            protocol=protocol,
            honeypot=honeypot,
            start_time=start_time,
            end_time=end_time,
            event_count=len(event_list),
            command_count=command_count,
            login_success_count=login_success_count,
            login_failure_count=login_failure_count,
        )

    @staticmethod
    def _resolve_identity(event_list: List[EnrichedEvent]) -> Tuple[str, str, str, str]:
        """Confirm session_id/source_ip/protocol/honeypot are consistent.

        Returns:
            The shared (session_id, source_ip, protocol, honeypot)
            values across every event.

        Raises:
            ValueError: If any event disagrees with the first event on
                session_id, source_ip, protocol, or honeypot.
        """
        first_event = event_list[0].processed_event.original_event
        session_id = first_event.session_id
        source_ip = first_event.source_ip
        protocol = first_event.protocol
        honeypot = first_event.honeypot

        for enriched in event_list[1:]:
            original_event = enriched.processed_event.original_event

            if original_event.session_id != session_id:
                raise ValueError(
                    "Events belong to different sessions: "
                    f"{session_id!r} vs {original_event.session_id!r}."
                )
            if original_event.source_ip != source_ip:
                raise ValueError(
                    "Events have inconsistent source_ip: "
                    f"{source_ip!r} vs {original_event.source_ip!r}."
                )
            if original_event.protocol != protocol:
                raise ValueError(
                    "Events have inconsistent protocol: "
                    f"{protocol!r} vs {original_event.protocol!r}."
                )
            if original_event.honeypot != honeypot:
                raise ValueError(
                    "Events have inconsistent honeypot: "
                    f"{honeypot!r} vs {original_event.honeypot!r}."
                )

        return session_id, source_ip, protocol, honeypot