"""Tests for the SecureTrap AttackEvent data model."""

from core.event_engine.event import AttackEvent


def test_attack_event_creation():
    """AttackEvent should store all provided fields correctly."""

    event = AttackEvent(
        timestamp="2026-08-11T18:30:00",
        source_ip="192.168.1.10",
        session_id="session001",
        protocol="SSH",
        command="ls -la",
        event_type="command",
        honeypot="Cowrie",
    )

    assert event.timestamp == "2026-08-11T18:30:00"
    assert event.source_ip == "192.168.1.10"
    assert event.session_id == "session001"
    assert event.protocol == "SSH"
    assert event.command == "ls -la"
    assert event.event_type == "command"
    assert event.honeypot == "Cowrie"