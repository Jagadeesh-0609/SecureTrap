"""Standardized internal event representation for SecureTrap.

AttackEvent is the common data contract that every honeypot adapter
produces. Downstream components consume AttackEvent objects instead of
honeypot-specific raw log formats.
"""

from dataclasses import dataclass


@dataclass
class AttackEvent:
    """A single normalized security event captured by a honeypot.

    This is the standard internal representation used throughout
    SecureTrap. Each honeypot adapter is responsible for translating
    its native log format into an AttackEvent.

    Attributes:
        timestamp: ISO 8601 timestamp of when the event occurred.
        source_ip: IP address of the attacker/client.
        session_id: Identifier for the honeypot session.
        protocol: Protocol involved in the event, such as SSH or FTP.
        command: Command or payload associated with the event.
        event_type: Category of the event, such as command or login.
        honeypot: Name of the honeypot that generated the event.
    """

    timestamp: str
    source_ip: str
    session_id: str
    protocol: str
    command: str
    event_type: str
    honeypot: str