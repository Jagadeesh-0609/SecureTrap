"""Event validation interface for SecureTrap.

Provides a single reusable entry point for validating normalized
event data against AttackEventSchema.
"""

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from pydantic import ValidationError

from core.event_engine.schema import AttackEventSchema


@dataclass
class ValidationResult:
    """Outcome of validating a single event.

    Attributes:
        valid: Whether the input passed schema validation.
        event: The validated AttackEventSchema on success,
            otherwise None.
        errors: Human-readable validation error messages.
    """

    valid: bool
    event: Optional[AttackEventSchema]
    errors: list[str] = field(default_factory=list)


def validate_event(data: Mapping[str, Any]) -> ValidationResult:
    """Validate normalized event data against AttackEventSchema.

    Args:
        data: Mapping containing normalized event fields.

    Returns:
        ValidationResult containing the validation status,
        validated event, and any validation errors.
    """
    try:
        event = AttackEventSchema(**data)
    except ValidationError as exc:
        errors = [
            f"{'.'.join(str(part) for part in error['loc'])}: "
            f"{error['msg']}"
            for error in exc.errors()
        ]

        return ValidationResult(
            valid=False,
            event=None,
            errors=errors,
        )

    return ValidationResult(
        valid=True,
        event=event,
        errors=[],
    )