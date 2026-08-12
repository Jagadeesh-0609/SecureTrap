"""Tests for the SecureTrap Cowrie honeypot adapter."""

from core.event_engine.event import AttackEvent
from core.honeypot_engine.cowrie_adapter import CowrieAdapter


COMMAND_EVENT = {
    "eventid": "cowrie.command.input",
    "timestamp": "2026-08-12T14:20:00.123456Z",
    "src_ip": "127.0.0.1",
    "session": "7e40868a3c49",
    "protocol": "ssh",
    "input": "pwd",
}


LOGIN_EVENT = {
    "eventid": "cowrie.login.success",
    "timestamp": "2026-08-12T14:20:00.123456Z",
    "src_ip": "127.0.0.1",
    "session": "7e40868a3c49",
    "protocol": "ssh",
    "username": "root",
}


def test_command_event_converts_to_attack_event():
    event = CowrieAdapter().parse_event(COMMAND_EVENT)

    assert isinstance(event, AttackEvent)


def test_timestamp_maps_correctly():
    event = CowrieAdapter().parse_event(COMMAND_EVENT)

    assert event.timestamp == "2026-08-12T14:20:00.123456Z"


def test_src_ip_maps_to_source_ip():
    event = CowrieAdapter().parse_event(COMMAND_EVENT)

    assert event.source_ip == "127.0.0.1"


def test_session_maps_to_session_id():
    event = CowrieAdapter().parse_event(COMMAND_EVENT)

    assert event.session_id == "7e40868a3c49"


def test_protocol_maps_correctly():
    event = CowrieAdapter().parse_event(COMMAND_EVENT)

    assert event.protocol == "ssh"


def test_eventid_maps_to_event_type():
    event = CowrieAdapter().parse_event(COMMAND_EVENT)

    assert event.event_type == "cowrie.command.input"


def test_input_maps_to_command():
    event = CowrieAdapter().parse_event(COMMAND_EVENT)

    assert event.command == "pwd"


def test_missing_input_produces_empty_command():
    event = CowrieAdapter().parse_event(LOGIN_EVENT)

    assert event.command == ""


def test_honeypot_is_always_cowrie():
    command_event = CowrieAdapter().parse_event(COMMAND_EVENT)
    login_event = CowrieAdapter().parse_event(LOGIN_EVENT)

    assert command_event.honeypot == "Cowrie"
    assert login_event.honeypot == "Cowrie"


def test_login_event_without_input_converts_correctly():
    event = CowrieAdapter().parse_event(LOGIN_EVENT)

    assert event.event_type == "cowrie.login.success"
    assert event.command == ""
    assert event.session_id == "7e40868a3c49"


def test_command_failed_event_converts_correctly():
    raw_event = {
        "eventid": "cowrie.command.failed",
        "timestamp": "2026-08-12T14:21:05.654321Z",
        "src_ip": "127.0.0.1",
        "session": "7e40868a3c49",
        "protocol": "ssh",
        "input": "nonexistent-command",
    }

    event = CowrieAdapter().parse_event(raw_event)

    assert event.event_type == "cowrie.command.failed"
    assert event.command == "nonexistent-command"


def test_extra_unknown_fields_do_not_break_conversion():
    raw_event = {
        "eventid": "cowrie.session.connect",
        "timestamp": "2026-08-12T14:19:58.000000Z",
        "src_ip": "127.0.0.1",
        "session": "7e40868a3c49",
        "protocol": "ssh",
        "src_port": 51884,
        "dst_ip": "10.0.0.5",
        "dst_port": 22,
        "system": "cowrie.ssh.factory.CowrieSSHFactory",
        "sensor": "my-honeypot",
    }

    event = CowrieAdapter().parse_event(raw_event)

    assert event.event_type == "cowrie.session.connect"
    assert event.command == ""
    assert event.source_ip == "127.0.0.1"