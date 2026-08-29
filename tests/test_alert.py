"""Isolated unit tests for AlertBuilder / Alert.

Uses directly constructed DatasetRecord and AnomalyResult objects.
Requires no Cowrie, no Docker, no network, no database, no real log
files, no sklearn, and no other external services.

Note: these tests only verify field copying and IsolationForest's own
inlier/outlier semantics. They never test or claim that is_anomaly
means an attack.
"""

import dataclasses
import inspect

from core.ai_engine.anomaly_result import AnomalyResult
from core.alert_engine.alert import Alert, AlertBuilder
from core.dataset_manager.builder import DatasetRecord


def _make_record(**overrides) -> DatasetRecord:
    defaults = dict(
        timestamp="2026-08-19T18:00:22.557428Z",
        source_ip="127.0.0.1",
        session_id="ce82815367a4",
        protocol="ssh",
        honeypot="Cowrie",
        event_type="cowrie.command.input",
        category="command_execution",
        severity="low",
        command="whomai",
        has_command=True,
        command_length=6,
        has_url=False,
        has_ip_address=False,
        has_file_path=False,
        has_shell_metacharacters=False,
    )
    defaults.update(overrides)
    return DatasetRecord(**defaults)


def _make_result(prediction: int = 1, score: float = 0.1, record=None) -> AnomalyResult:
    if record is None:
        record = _make_record()
    return AnomalyResult(
        record=record,
        prediction=prediction,
        score=score,
        is_anomaly=(prediction == -1),
    )


def test_anomaly_result_becomes_an_alert():
    alert = AlertBuilder().build(_make_result())
    assert isinstance(alert, Alert)


def test_timestamp_is_copied():
    record = _make_record(timestamp="2026-08-19T18:00:22.557428Z")
    alert = AlertBuilder().build(_make_result(record=record))
    assert alert.timestamp == "2026-08-19T18:00:22.557428Z"


def test_source_ip_is_copied():
    record = _make_record(source_ip="10.0.0.5")
    alert = AlertBuilder().build(_make_result(record=record))
    assert alert.source_ip == "10.0.0.5"


def test_session_id_is_copied():
    record = _make_record(session_id="ce82815367a4")
    alert = AlertBuilder().build(_make_result(record=record))
    assert alert.session_id == "ce82815367a4"


def test_protocol_is_copied():
    record = _make_record(protocol="telnet")
    alert = AlertBuilder().build(_make_result(record=record))
    assert alert.protocol == "telnet"


def test_honeypot_is_copied():
    record = _make_record(honeypot="Dionaea")
    alert = AlertBuilder().build(_make_result(record=record))
    assert alert.honeypot == "Dionaea"


def test_event_type_is_copied():
    record = _make_record(event_type="cowrie.login.failed")
    alert = AlertBuilder().build(_make_result(record=record))
    assert alert.event_type == "cowrie.login.failed"


def test_command_is_copied():
    record = _make_record(command="whomai")
    alert = AlertBuilder().build(_make_result(record=record))
    assert alert.command == "whomai"


def test_prediction_is_copied():
    alert = AlertBuilder().build(_make_result(prediction=1))
    assert alert.prediction == 1


def test_score_is_copied():
    alert = AlertBuilder().build(_make_result(score=0.10881753480914069))
    assert alert.score == 0.10881753480914069


def test_is_anomaly_is_copied():
    alert = AlertBuilder().build(_make_result(prediction=-1))
    assert alert.is_anomaly is True


def test_original_anomaly_result_identity_is_preserved():
    result = _make_result()
    alert = AlertBuilder().build(result)
    assert alert.result is result


def test_original_dataset_record_remains_reachable():
    record = _make_record(command="whomai")
    result = _make_result(record=record)
    alert = AlertBuilder().build(result)
    assert alert.result.record is record


def test_normal_result_can_also_be_represented_as_an_alert():
    alert = AlertBuilder().build(_make_result(prediction=1, score=0.5))
    assert alert.is_anomaly is False
    assert alert.prediction == 1


def test_anomalous_result_can_be_represented_as_an_alert():
    alert = AlertBuilder().build(_make_result(prediction=-1, score=-0.5))
    assert alert.is_anomaly is True
    assert alert.prediction == -1


def test_input_result_and_record_are_not_modified():
    record = _make_record(command="whomai")
    result = _make_result(prediction=1, score=0.1, record=record)
    original_command = record.command
    original_prediction = result.prediction
    original_score = result.score

    AlertBuilder().build(result)

    assert record.command == original_command
    assert result.prediction == original_prediction
    assert result.score == original_score


def test_repeated_builds_are_deterministic():
    result = _make_result(prediction=-1, score=-0.3)
    first = AlertBuilder().build(result)
    second = AlertBuilder().build(result)
    assert first == second


def test_no_attack_or_benign_classification_field_exists():
    alert_fields = {field.name for field in dataclasses.fields(Alert)}
    forbidden = {
        "attack_label",
        "benign_label",
        "malware",
        "brute_force",
        "threat_level",
        "confidence",
        "attack_type",
        "is_attack",
        "is_benign",
    }
    assert alert_fields.isdisjoint(forbidden)
    assert alert_fields == {
        "result",
        "timestamp",
        "source_ip",
        "session_id",
        "protocol",
        "honeypot",
        "event_type",
        "command",
        "prediction",
        "score",
        "is_anomaly",
    }


def test_builder_has_no_external_dependencies():
    import ast

    import core.alert_engine.alert as alert_module

    source = inspect.getsource(alert_module)
    tree = ast.parse(source)

    imported_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_names.add(alias.name.split(".")[0])
                if alias.asname:
                    imported_names.add(alias.asname)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_names.add(node.module.split(".")[0])
            for alias in node.names:
                imported_names.add(alias.asname or alias.name)

    forbidden_imports = {
        "CowrieAdapter",
        "JsonLogReader",
        "LiveJsonLogReader",
        "IngestionPipeline",
        "LogProcessor",
        "EventEnricher",
        "DatasetBuilder",
        "DatasetWriter",
        "ModelManager",
        "FeatureExtractor",
        "FeatureMatrixBuilder",
        "sklearn",
    }
    assert imported_names.isdisjoint(forbidden_imports)