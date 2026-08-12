"""Cowrie honeypot adapter for SecureTrap.

Converts a raw Cowrie JSON event into the normalized AttackEvent model.

Cowrie-specific field knowledge is intentionally contained in this
module so that downstream SecureTrap components remain honeypot-independent.
"""

from typing import Any, Mapping

from core.event_engine.event import AttackEvent
from core.honeypot_engine.base_adapter import BaseAdapter


class CowrieAdapter(BaseAdapter):
    """Convert Cowrie events into SecureTrap AttackEvent objects."""

    def parse_event(self, raw_event: Mapping[str, Any]) -> AttackEvent:
        """Convert one raw Cowrie event into an AttackEvent.

        Args:
            raw_event: A decoded Cowrie JSON event.

        Returns:
            A normalized AttackEvent.

        Raises:
            KeyError: If a required Cowrie field is missing.
        """
        return AttackEvent(
            timestamp=raw_event["timestamp"],
            source_ip=raw_event["src_ip"],
            session_id=raw_event["session"],
            protocol=raw_event["protocol"],
            command=raw_event.get("input", ""),
            event_type=raw_event["eventid"],
            honeypot="Cowrie",
        )