"""Base adapter contract for SecureTrap honeypot integrations.

Defines the interface every honeypot adapter must implement to convert
a honeypot's native event format into the standard AttackEvent model.
"""

from abc import ABC, abstractmethod
from typing import Any, Mapping

from core.event_engine.event import AttackEvent


class BaseAdapter(ABC):
    """Contract for converting a raw honeypot event into an AttackEvent.

    Each supported honeypot implements this interface with its own
    adapter. Downstream SecureTrap components work with AttackEvent
    rather than honeypot-specific log formats.
    """

    @abstractmethod
    def parse_event(self, raw_event: Mapping[str, Any]) -> AttackEvent:
        """Convert one raw honeypot event into an AttackEvent.

        Args:
            raw_event: Native event representation produced by a
                honeypot.

        Returns:
            A normalized AttackEvent.
        """
        raise NotImplementedError