"""Isolated unit tests for AlertStore.

Uses pytest's tmp_path fixture exclusively, so tests never touch the
project-root database. Requires no Cowrie, no Docker, no network, no
sklearn, and no other external services — sqlite3 + standard library
only.
"""

import ast
import inspect
import sqlite3

import pytest

from core.ai_engine.anomaly_result import AnomalyResult
from core.alert_engine.alert import Alert
from core.alert_engine.alert_store import AlertStore
from core.dataset_manager.builder import DatasetRecord


def _make_alert(
    timestamp="2026-08-19T18:00:22.557428Z",
    source_ip="127.0.0.1",
    session_id="ce82815367a4",
    protocol="ssh",
    honeypot="Cowrie",
    event_type="cowrie.command.input",
    command="pwd",
    prediction=1,
    score=0.1,
) -> Alert:
    record = DatasetRecord(
        timestamp=timestamp,
        source_ip=source_ip,
        session_id=session_id,
        protocol=protocol,
        honeypot=honeypot,
        event_type=event_type,
        category="command_execution",
        severity="low",
        command=command,
        has_command=bool(command),
        command_length=len(command),
        has_url=False,
        has_ip_address=False,
        has_file_path=False,
        has_shell_metacharacters=False,
    )
    result = AnomalyResult(
        record=record,
        prediction=prediction,
        score=score,
        is_anomaly=(prediction == -1),
    )
    return Alert(
        result=result,
        timestamp=timestamp,
        source_ip=source_ip,
        session_id=session_id,
        protocol=protocol,
        honeypot=honeypot,
        event_type=event_type,
        command=command,
        prediction=prediction,
        score=score,
        is_anomaly=(prediction == -1),
    )


def test_initializing_a_store_creates_the_database_file(tmp_path):
    db_path = tmp_path / "alerts.db"
    AlertStore(db_path)
    assert db_path.exists()


def test_initializing_a_store_creates_the_alerts_table(tmp_path):
    db_path = tmp_path / "alerts.db"
    AlertStore(db_path)

    connection = sqlite3.connect(db_path)
    try:
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'"
        ).fetchall()
    finally:
        connection.close()

    assert len(tables) == 1


def test_saving_an_alert_returns_an_integer_id(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    alert_id = store.save(_make_alert())
    assert isinstance(alert_id, int)


def test_saved_alert_can_be_retrieved_by_id(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    alert_id = store.save(_make_alert(command="pwd"))

    retrieved = store.get_by_id(alert_id)

    assert retrieved is not None
    assert retrieved.command == "pwd"


def test_all_persisted_fields_round_trip_correctly(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    original = _make_alert(
        timestamp="2026-08-19T18:04:42.103477Z",
        source_ip="10.0.0.9",
        session_id="ce82815367a4",
        protocol="telnet",
        honeypot="Dionaea",
        event_type="cowrie.login.failed",
        command="echo http://1.2.3.4",
        prediction=-1,
        score=-0.42,
    )

    alert_id = store.save(original)
    retrieved = store.get_by_id(alert_id)

    assert retrieved.timestamp == original.timestamp
    assert retrieved.source_ip == original.source_ip
    assert retrieved.session_id == original.session_id
    assert retrieved.protocol == original.protocol
    assert retrieved.honeypot == original.honeypot
    assert retrieved.event_type == original.event_type
    assert retrieved.command == original.command
    assert retrieved.prediction == original.prediction
    assert retrieved.score == original.score
    assert retrieved.is_anomaly == original.is_anomaly


def test_prediction_remains_int_and_preserves_values(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    normal_id = store.save(_make_alert(prediction=1))
    anomaly_id = store.save(_make_alert(prediction=-1))

    normal = store.get_by_id(normal_id)
    anomaly = store.get_by_id(anomaly_id)

    assert normal.prediction == 1
    assert isinstance(normal.prediction, int)
    assert anomaly.prediction == -1
    assert isinstance(anomaly.prediction, int)


def test_score_round_trips_as_float(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    alert_id = store.save(_make_alert(score=0.10881753480914069))

    retrieved = store.get_by_id(alert_id)

    assert isinstance(retrieved.score, float)
    assert retrieved.score == pytest.approx(0.10881753480914069)


def test_is_anomaly_round_trips_as_bool(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    anomaly_id = store.save(_make_alert(prediction=-1))
    normal_id = store.save(_make_alert(prediction=1))

    anomaly = store.get_by_id(anomaly_id)
    normal = store.get_by_id(normal_id)

    assert anomaly.is_anomaly is True
    assert normal.is_anomaly is False


def test_timestamp_is_preserved_exactly(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    alert_id = store.save(_make_alert(timestamp="2026-08-19T18:00:22.557428Z"))

    retrieved = store.get_by_id(alert_id)

    assert retrieved.timestamp == "2026-08-19T18:00:22.557428Z"


def test_command_is_preserved_exactly_including_commas_and_quotes(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    tricky_command = 'echo "hello, world", it\'s a test'
    alert_id = store.save(_make_alert(command=tricky_command))

    retrieved = store.get_by_id(alert_id)

    assert retrieved.command == tricky_command


def test_multiple_alerts_can_be_stored(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    store.save(_make_alert(command="a"))
    store.save(_make_alert(command="b"))
    store.save(_make_alert(command="c"))

    assert store.count() == 3


def test_list_recent_returns_newest_first(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    store.save(_make_alert(command="first"))
    store.save(_make_alert(command="second"))
    store.save(_make_alert(command="third"))

    recent = store.list_recent()

    assert [alert.command for alert in recent] == ["third", "second", "first"]


def test_list_recent_respects_limit(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    for command in ["a", "b", "c", "d", "e"]:
        store.save(_make_alert(command=command))

    recent = store.list_recent(limit=2)

    assert len(recent) == 2
    assert [alert.command for alert in recent] == ["e", "d"]


def test_invalid_limit_raises_value_error(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    store.save(_make_alert())

    with pytest.raises(ValueError):
        store.list_recent(limit=0)

    with pytest.raises(ValueError):
        store.list_recent(limit=-5)


def test_get_by_id_returns_none_for_unknown_id(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    assert store.get_by_id(999) is None


def test_count_returns_correct_number(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    assert store.count() == 0

    store.save(_make_alert())
    store.save(_make_alert())

    assert store.count() == 2


def test_parent_directories_are_created_automatically(tmp_path):
    db_path = tmp_path / "nested" / "data" / "alerts.db"
    AlertStore(db_path)
    assert db_path.exists()


def test_newly_initialized_store_has_zero_alerts(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    assert store.count() == 0
    assert store.list_recent() == []


def test_normal_alert_objects_can_be_persisted(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    alert_id = store.save(_make_alert(prediction=1))

    retrieved = store.get_by_id(alert_id)

    assert retrieved.is_anomaly is False
    assert retrieved.prediction == 1


def test_anomalous_alert_objects_can_be_persisted(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    alert_id = store.save(_make_alert(prediction=-1))

    retrieved = store.get_by_id(alert_id)

    assert retrieved.is_anomaly is True
    assert retrieved.prediction == -1


def test_database_operations_do_not_modify_the_input_alert(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    alert = _make_alert(command="pwd", prediction=1, score=0.1)
    original_command = alert.command
    original_prediction = alert.prediction
    original_score = alert.score

    store.save(alert)

    assert alert.command == original_command
    assert alert.prediction == original_prediction
    assert alert.score == original_score


def test_no_model_ai_or_logging_dependencies_are_imported():
    import core.alert_engine.alert_store as store_module

    source = inspect.getsource(store_module)
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
        "ModelManager",
        "AnomalyDetector",
        "FeatureExtractor",
        "FeatureMatrixBuilder",
        "LiveDetectionPipeline",
        "AlertDispatcher",
        "CowrieAdapter",
        "LogReader",
        "IngestionPipeline",
        "LogProcessor",
        "EventEnricher",
        "DatasetWriter",
        "sklearn",
        "logging",
    }
    assert imported_names.isdisjoint(forbidden_imports)