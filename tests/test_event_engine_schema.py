"""Tests for the SecureTrap AttackEvent schema."""

import pytest
from pydantic import ValidationError

from core.event_engine.schema import AttackEventSchema


VALID_EVENT = {
    "timestamp": "2026-08-11T18:30:00",
    "source_ip": "192.168.1.10",
    "session_id": "session001",
    "protocol": "SSH",
    "command": "ls -la",
    "event_type": "command",
    "honeypot": "Cowrie",
}


def test_valid_event_passes():
    event = AttackEventSchema(**VALID_EVENT)

    assert event.source_ip == "192.168.1.10"
    assert event.honeypot == "Cowrie"


def test_invalid_ip_address_rejected():
    data = {**VALID_EVENT, "source_ip": "999.999.999.999"}

    with pytest.raises(ValidationError):
        AttackEventSchema(**data)


def test_invalid_timestamp_rejected():
    data = {**VALID_EVENT, "timestamp": "not-a-timestamp"}

    with pytest.raises(ValidationError):
        AttackEventSchema(**data)


def test_empty_session_id_rejected():
    data = {**VALID_EVENT, "session_id": "   "}

    with pytest.raises(ValidationError):
        AttackEventSchema(**data)


def test_empty_protocol_rejected():
    data = {**VALID_EVENT, "protocol": ""}

    with pytest.raises(ValidationError):
        AttackEventSchema(**data)


def test_empty_event_type_rejected():
    data = {**VALID_EVENT, "event_type": "  "}

    with pytest.raises(ValidationError):
        AttackEventSchema(**data)


def test_empty_honeypot_rejected():
    data = {**VALID_EVENT, "honeypot": ""}

    with pytest.raises(ValidationError):
        AttackEventSchema(**data)


def test_empty_command_accepted():
    data = {
        **VALID_EVENT,
        "command": "",
        "event_type": "login",
    }

    event = AttackEventSchema(**data)

    assert event.command == ""


def test_non_ssh_protocol_accepted():
    data = {**VALID_EVENT, "protocol": "FTP"}

    event = AttackEventSchema(**data)

    assert event.protocol == "FTP"


def test_non_cowrie_honeypot_accepted():
    data = {**VALID_EVENT, "honeypot": "Dionaea"}

    event = AttackEventSchema(**data)

    assert event.honeypot == "Dionaea"