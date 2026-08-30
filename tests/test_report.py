"""Isolated unit tests for AlertReporter / AlertSummary.

Uses a fake AlertStore for orchestration tests, plus one small
real-AlertStore integration check via tmp_path. Requires no Cowrie,
no Docker, no network, no sklearn, and no other external services.

Note: these tests only verify counts/ordering and IsolationForest's
own inlier/outlier semantics as already stored. They never claim a
stored alert represents a confirmed attack.
"""

import ast
import dataclasses
import inspect

import pytest

from core.ai_engine.anomaly_result import AnomalyResult
from core.alert_engine.alert import Alert
from core.alert_engine.alert_store import AlertStore
from core.alert_engine.report import AlertReporter, AlertSummary
from core.dataset_manager.builder import DatasetRecord


def _make_alert(
    timestamp: str = "2026-08-19T18:00:22.557428Z",
    command: str = "pwd",
    prediction: int = 1,
    score: float = 0.1,
) -> Alert:
    record = DatasetRecord(
        timestamp=timestamp,
        source_ip="127.0.0.1",
        session_id="ce82815367a4",
        protocol="ssh",
        honeypot="Cowrie",
        event_type="cowrie.command.input",
        category="command_execution",
        severity="low",
        command=command,
        has_command=True,
        command_length=len(command),
        has_url=False,
        has_ip_address=False,
        has_file_path=False,
        has_shell_metacharacters=False,
    )
    result = AnomalyResult(record=record, prediction=prediction, score=score, is_anomaly=(prediction == -1))
    return Alert(
        result=result,
        timestamp=timestamp,
        source_ip=record.source_ip,
        session_id=record.session_id,
        protocol=record.protocol,
        honeypot=record.honeypot,
        event_type=record.event_type,
        command=command,
        prediction=prediction,
        score=score,
        is_anomaly=(prediction == -1),
    )


class _FakeAlertStore:
    """In-memory fake AlertStore mirroring count()/list_recent() semantics.

    `alerts` should be given oldest-first (insertion order), matching
    how they'd have been save()'d; list_recent() returns them
    newest-first, exactly like the real AlertStore.
    """

    def __init__(self, alerts=None):
        self._alerts = list(alerts) if alerts is not None else []
        self.list_recent_calls = []

    def count(self):
        return len(self._alerts)

    def list_recent(self, limit=100):
        if limit <= 0:
            raise ValueError(f"limit must be a positive integer, got {limit!r}.")
        self.list_recent_calls.append(limit)
        return list(reversed(self._alerts))[:limit]


def test_empty_store_produces_zero_summary():
    reporter = AlertReporter(_FakeAlertStore(alerts=[]))
    summary = reporter.summary()

    assert summary.total_alerts == 0
    assert summary.anomaly_alerts == 0
    assert summary.normal_alerts == 0


def test_empty_store_has_latest_timestamp_none():
    reporter = AlertReporter(_FakeAlertStore(alerts=[]))
    summary = reporter.summary()

    assert summary.latest_timestamp is None


def test_one_anomaly_alert_is_counted_correctly():
    reporter = AlertReporter(_FakeAlertStore(alerts=[_make_alert(prediction=-1)]))
    summary = reporter.summary()

    assert summary.total_alerts == 1
    assert summary.anomaly_alerts == 1
    assert summary.normal_alerts == 0


def test_one_normal_alert_is_counted_correctly():
    reporter = AlertReporter(_FakeAlertStore(alerts=[_make_alert(prediction=1)]))
    summary = reporter.summary()

    assert summary.total_alerts == 1
    assert summary.anomaly_alerts == 0
    assert summary.normal_alerts == 1


def test_mixed_alerts_are_counted_correctly():
    alerts = [
        _make_alert(prediction=1, command="a"),
        _make_alert(prediction=-1, command="b"),
        _make_alert(prediction=1, command="c"),
        _make_alert(prediction=-1, command="d"),
        _make_alert(prediction=-1, command="e"),
    ]
    reporter = AlertReporter(_FakeAlertStore(alerts=alerts))
    summary = reporter.summary()

    assert summary.total_alerts == 5
    assert summary.anomaly_alerts == 3
    assert summary.normal_alerts == 2


def test_anomaly_and_normal_counts_sum_to_total():
    alerts = [_make_alert(prediction=1), _make_alert(prediction=-1), _make_alert(prediction=1)]
    reporter = AlertReporter(_FakeAlertStore(alerts=alerts))
    summary = reporter.summary()

    assert summary.anomaly_alerts + summary.normal_alerts == summary.total_alerts


def test_latest_timestamp_comes_from_newest_stored_alert():
    alerts = [
        _make_alert(timestamp="2026-08-19T18:00:00.000000Z", command="first"),
        _make_alert(timestamp="2026-08-19T18:01:00.000000Z", command="second"),
        _make_alert(timestamp="2026-08-19T18:02:00.000000Z", command="third"),
    ]
    reporter = AlertReporter(_FakeAlertStore(alerts=alerts))
    summary = reporter.summary()

    assert summary.latest_timestamp == "2026-08-19T18:02:00.000000Z"


def test_recent_delegates_to_alert_store_list_recent():
    store = _FakeAlertStore(alerts=[_make_alert(command="a"), _make_alert(command="b")])
    reporter = AlertReporter(store)

    reporter.recent(limit=5)

    assert store.list_recent_calls == [5]


def test_recent_preserves_order():
    alerts = [
        _make_alert(command="first"),
        _make_alert(command="second"),
        _make_alert(command="third"),
    ]
    reporter = AlertReporter(_FakeAlertStore(alerts=alerts))

    recent = reporter.recent()

    assert [alert.command for alert in recent] == ["third", "second", "first"]


def test_recent_forwards_limit_correctly():
    alerts = [_make_alert(command=str(i)) for i in range(5)]
    reporter = AlertReporter(_FakeAlertStore(alerts=alerts))

    recent = reporter.recent(limit=2)

    assert len(recent) == 2
    assert [alert.command for alert in recent] == ["4", "3"]


def test_invalid_limit_propagates():
    reporter = AlertReporter(_FakeAlertStore(alerts=[_make_alert()]))

    with pytest.raises(ValueError):
        reporter.recent(limit=0)


def test_alert_objects_returned_by_recent_are_unchanged():
    original = _make_alert(command="pwd", prediction=-1, score=-0.4)
    reporter = AlertReporter(_FakeAlertStore(alerts=[original]))

    recent = reporter.recent()

    assert recent[0].command == "pwd"
    assert recent[0].prediction == -1
    assert recent[0].score == -0.4


def test_database_is_not_modified_by_summary():
    store = _FakeAlertStore(alerts=[_make_alert(command="a"), _make_alert(command="b")])
    reporter = AlertReporter(store)
    snapshot_before = list(store._alerts)

    reporter.summary()

    assert store._alerts == snapshot_before


def test_database_is_not_modified_by_recent():
    store = _FakeAlertStore(alerts=[_make_alert(command="a"), _make_alert(command="b")])
    reporter = AlertReporter(store)
    snapshot_before = list(store._alerts)

    reporter.recent()

    assert store._alerts == snapshot_before


def test_recent_returns_a_plain_list_not_a_generator():
    reporter = AlertReporter(_FakeAlertStore(alerts=[_make_alert()]))
    result = reporter.recent()

    assert isinstance(result, list)


def test_dependency_injection_works_with_fake_alert_store():
    store = _FakeAlertStore(alerts=[_make_alert(prediction=-1)])
    reporter = AlertReporter(store)

    summary = reporter.summary()

    assert summary.total_alerts == 1
    assert summary.anomaly_alerts == 1


def test_no_ai_model_or_honeypot_dependencies_are_imported():
    import core.alert_engine.report as report_module

    source = inspect.getsource(report_module)
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
        "AlertBuilder",
        "DatasetBuilder",
        "CowrieAdapter",
        "LogReader",
        "IngestionPipeline",
        "LogProcessor",
        "EventEnricher",
        "sklearn",
    }
    assert imported_names.isdisjoint(forbidden_imports)


def test_no_attack_benign_or_security_classification_fields_introduced():
    summary_fields = {field.name for field in dataclasses.fields(AlertSummary)}
    forbidden = {
        "attack_count",
        "benign_count",
        "threat_level",
        "confidence",
        "is_attack",
        "is_benign",
        "attack_alerts",
    }
    assert summary_fields.isdisjoint(forbidden)
    assert summary_fields == {
        "total_alerts",
        "anomaly_alerts",
        "normal_alerts",
        "latest_timestamp",
    }


def test_repeated_summary_calls_are_deterministic():
    alerts = [_make_alert(prediction=1), _make_alert(prediction=-1)]
    reporter = AlertReporter(_FakeAlertStore(alerts=alerts))

    first = reporter.summary()
    second = reporter.summary()

    assert first == second


def test_real_alert_store_integration(tmp_path):
    store = AlertStore(tmp_path / "alerts.db")
    store.save(_make_alert(prediction=1, command="pwd"))
    store.save(_make_alert(prediction=-1, command="echo http://1.2.3.4"))

    reporter = AlertReporter(store)
    summary = reporter.summary()
    recent = reporter.recent(limit=1)

    assert summary.total_alerts == 2
    assert summary.anomaly_alerts == 1
    assert summary.normal_alerts == 1
    assert len(recent) == 1
    assert recent[0].command == "echo http://1.2.3.4"