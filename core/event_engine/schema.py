"""SecureTrap Event Schema.

Defines the structural validation rules for an AttackEvent using
Pydantic. The AttackEvent dataclass remains a simple data carrier,
while this schema is responsible for structural validation.

The schema is deliberately honeypot-independent. It validates the
shape of event data without assuming a specific honeypot, protocol,
or event type.
"""

from datetime import datetime
from ipaddress import ip_address

from pydantic import BaseModel, ValidationInfo, field_validator


class AttackEventSchema(BaseModel):
    """Pydantic schema for validating SecureTrap attack events.

    Attributes:
        timestamp: ISO-8601 timestamp of when the event occurred.
        source_ip: IPv4 or IPv6 address associated with the event.
        session_id: Identifier for the honeypot session.
        protocol: Protocol involved in the event.
        command: Command or payload associated with the event.
        event_type: Category of the security event.
        honeypot: Name of the honeypot that generated the event.
    """

    timestamp: str
    source_ip: str
    session_id: str
    protocol: str
    command: str
    event_type: str
    honeypot: str

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: str) -> str:
        """Reject values that are not valid ISO-8601 timestamps."""
        try:
            datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError(
                f"timestamp must be a valid ISO-8601 timestamp: {value!r}"
            ) from exc

        return value

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str) -> str:
        """Reject values that are not valid IPv4 or IPv6 addresses."""
        try:
            ip_address(value)
        except ValueError as exc:
            raise ValueError(
                f"source_ip must be a valid IPv4 or IPv6 address: {value!r}"
            ) from exc

        return value

    @field_validator("session_id", "protocol", "event_type", "honeypot")
    @classmethod
    def validate_non_blank(
        cls,
        value: str,
        info: ValidationInfo,
    ) -> str:
        """Reject empty or whitespace-only required fields."""
        if not value.strip():
            raise ValueError(
                f"{info.field_name} must not be empty or whitespace-only"
            )

        return value