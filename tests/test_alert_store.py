"""Isolated unit tests for AlertStore.

Uses pytest's tmp_path fixture exclusively, so tests never touch the
project-root database. Requires no Cowrie, no Docker, no network, no
sklearn, and no other external services — sqlite3 + standard library
only.
"""

import ast
import dataclasses
import inspect
import sqlite3

import pytest

from core.ai_engine.anomaly_result import AnomalyResult
from core.alert_engine.alert import Alert
from core.alert_engine.alert_store import AlertStatistics, AlertStore, StoredAlert
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


# --------------------------------------------------------------------
# StoredAlert / get_stored_by_id / list_recent_stored (Phase 8.0)
# --------------------------------------------------------------------


def test_stored_alert_holds_the_given_id_and_alert():
    alert = _make_alert(command="pwd")

    stored = StoredAlert(id=7, alert=alert)

    assert stored.id == 7
    assert stored.alert is alert


def test_stored_alert_has_exactly_id_and_alert_fields():
    assert {field.name for field in dataclasses.fields(StoredAlert)} == {"id", "alert"}


def test_stored_alert_is_immutable():
    stored = StoredAlert(id=1, alert=_make_alert())

    with pytest.raises(dataclasses.FrozenInstanceError):
        stored.id = 2

    with pytest.raises(dataclasses.FrozenInstanceError):
        stored.alert = _make_alert(command="other")


def test_alert_itself_still_has_no_id_attribute(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    alert_id = store.save(_make_alert())

    assert not hasattr(store.get_by_id(alert_id), "id")
    assert not hasattr(store.get_stored_by_id(alert_id).alert, "id")
    assert "id" not in {field.name for field in dataclasses.fields(Alert)}


def test_get_stored_by_id_returns_the_id_from_save_and_the_matching_alert(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    store.save(_make_alert(command="other"))
    alert_id = store.save(_make_alert(command="whoami", prediction=-1, score=-0.42))

    stored = store.get_stored_by_id(alert_id)

    assert isinstance(stored, StoredAlert)
    assert stored.id == alert_id
    assert isinstance(stored.alert, Alert)
    assert stored.alert.command == "whoami"
    assert stored.alert.prediction == -1
    assert stored.alert.score == pytest.approx(-0.42)
    assert stored.alert.is_anomaly is True


def test_get_stored_by_id_matches_get_by_id(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    alert_id = store.save(_make_alert(command="uname -a", prediction=-1, score=-0.3))

    assert store.get_stored_by_id(alert_id).alert == store.get_by_id(alert_id)


def test_get_stored_by_id_returns_none_for_unknown_id(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    assert store.get_stored_by_id(999) is None

    alert_id = store.save(_make_alert())
    assert store.get_stored_by_id(alert_id + 1) is None


def test_list_recent_stored_returns_stored_alerts_newest_first(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    saved_ids = [store.save(_make_alert(command=c)) for c in ["first", "second", "third"]]

    recent = store.list_recent_stored()

    assert all(isinstance(item, StoredAlert) for item in recent)
    assert [item.alert.command for item in recent] == ["third", "second", "first"]
    assert [item.id for item in recent] == list(reversed(saved_ids))


def test_list_recent_stored_ids_match_the_database_records(tmp_path):
    db_path = tmp_path / "alerts.db"
    store = AlertStore(db_path)
    for command in ["a", "b", "c", "d"]:
        store.save(_make_alert(command=command))

    connection = sqlite3.connect(db_path)
    try:
        rows = connection.execute(
            "SELECT id, command FROM alerts ORDER BY id DESC"
        ).fetchall()
    finally:
        connection.close()

    recent = store.list_recent_stored()

    assert [(item.id, item.alert.command) for item in recent] == rows


def test_list_recent_stored_respects_limit(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    saved_ids = [store.save(_make_alert(command=c)) for c in ["a", "b", "c", "d", "e"]]

    recent = store.list_recent_stored(limit=2)

    assert len(recent) == 2
    assert [item.alert.command for item in recent] == ["e", "d"]
    assert [item.id for item in recent] == [saved_ids[4], saved_ids[3]]
    # A limit larger than the store returns everything, newest first.
    assert len(store.list_recent_stored(limit=50)) == 5


def test_list_recent_stored_invalid_limit_raises_value_error(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    store.save(_make_alert())

    with pytest.raises(ValueError):
        store.list_recent_stored(limit=0)

    with pytest.raises(ValueError):
        store.list_recent_stored(limit=-5)


def test_list_recent_stored_on_empty_store_returns_empty_list(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    assert store.list_recent_stored() == []


def test_list_recent_stored_has_same_alerts_and_order_as_list_recent(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    for index in range(6):
        store.save(_make_alert(command=f"cmd-{index}", prediction=-1 if index % 2 else 1))

    for limit in (1, 3, 6, 100):
        assert [item.alert for item in store.list_recent_stored(limit=limit)] == store.list_recent(
            limit=limit
        )


def test_existing_read_methods_keep_their_original_return_types(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    alert_id = store.save(_make_alert(command="pwd"))
    store.save(_make_alert(command="ls"))

    assert isinstance(alert_id, int)
    assert type(store.get_by_id(alert_id)) is Alert
    assert store.get_by_id(999) is None
    recent = store.list_recent()
    assert isinstance(recent, list)
    assert all(type(item) is Alert for item in recent)
    assert isinstance(store.count(), int)
    assert isinstance(store.get_statistics(), AlertStatistics)


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