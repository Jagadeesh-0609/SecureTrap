"""Tests for the SecureTrap event validator."""

from core.event_engine.schema import AttackEventSchema
from core.event_engine.validator import validate_event


VALID_EVENT = {
    "timestamp": "2026-08-11T18:30:00",
    "source_ip": "192.168.1.10",
    "session_id": "session001",
    "protocol": "SSH",
    "command": "ls -la",
    "event_type": "command",
    "honeypot": "Cowrie",
}


def test_valid_event_is_valid():
    result = validate_event(VALID_EVENT)

    assert result.valid is True


def test_valid_event_contains_schema_object():
    result = validate_event(VALID_EVENT)

    assert isinstance(result.event, AttackEventSchema)


def test_valid_event_has_no_errors():
    result = validate_event(VALID_EVENT)

    assert result.errors == []


def test_invalid_ip_is_invalid():
    data = {**VALID_EVENT, "source_ip": "999.999.999.999"}

    result = validate_event(data)

    assert result.valid is False


def test_invalid_timestamp_is_invalid():
    data = {**VALID_EVENT, "timestamp": "not-a-timestamp"}

    result = validate_event(data)

    assert result.valid is False


def test_missing_required_field_is_invalid():
    data = {
        key: value
        for key, value in VALID_EVENT.items()
        if key != "protocol"
    }

    result = validate_event(data)

    assert result.valid is False


def test_invalid_event_has_none_event():
    data = {**VALID_EVENT, "source_ip": "not-an-ip"}

    result = validate_event(data)

    assert result.event is None


def test_invalid_event_has_useful_errors():
    data = {**VALID_EVENT, "source_ip": "not-an-ip"}

    result = validate_event(data)

    assert len(result.errors) > 0
    assert any("source_ip" in error for error in result.errors)


def test_empty_command_is_accepted():
    data = {
        **VALID_EVENT,
        "command": "",
        "event_type": "login",
    }

    result = validate_event(data)

    assert result.valid is True
    assert result.event.command == ""


def test_non_cowrie_honeypot_is_accepted():
    data = {**VALID_EVENT, "honeypot": "Dionaea"}

    result = validate_event(data)

    assert result.valid is True
    assert result.event.honeypot == "Dionaea"


def test_non_ssh_protocol_is_accepted():
    data = {**VALID_EVENT, "protocol": "FTP"}

    result = validate_event(data)

    assert result.valid is True
    assert result.event.protocol == "FTP"