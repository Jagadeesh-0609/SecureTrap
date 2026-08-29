"""Isolated unit tests for AlertDispatcher.

Uses directly constructed DatasetRecord and AnomalyResult objects.
Requires no Cowrie, no Docker, no network, no database, no real log
files, no sklearn, and no other external services.

Note: these tests only verify filtering/orchestration and
IsolationForest's own inlier/outlier semantics. They never test or
claim that an alert represents a confirmed attack.
"""

import ast
import inspect

from core.ai_engine.anomaly_result import AnomalyResult
from core.alert_engine.alert import Alert
from core.dataset_manager.builder import DatasetRecord
from core.runtime.alert_dispatch import AlertDispatcher


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
        command="pwd",
        has_command=True,
        command_length=3,
        has_url=False,
        has_ip_address=False,
        has_file_path=False,
        has_shell_metacharacters=False,
    )
    defaults.update(overrides)
    return DatasetRecord(**defaults)


def _make_result(prediction: int = 1, score: float = 0.1, command: str = "pwd") -> AnomalyResult:
    return AnomalyResult(
        record=_make_record(command=command),
        prediction=prediction,
        score=score,
        is_anomaly=(prediction == -1),
    )


class _FakeAlertBuilder:
    """Fake AlertBuilder that records inputs and returns a real Alert."""

    def __init__(self):
        self.build_calls = []

    def build(self, result):
        self.build_calls.append(result)
        record = result.record
        return Alert(
            result=result,
            timestamp=record.timestamp,
            source_ip=record.source_ip,
            session_id=record.session_id,
            protocol=record.protocol,
            honeypot=record.honeypot,
            event_type=record.event_type,
            command=record.command,
            prediction=result.prediction,
            score=result.score,
            is_anomaly=result.is_anomaly,
        )


def test_normal_result_produces_no_alert():
    dispatcher = AlertDispatcher()
    alerts = list(dispatcher.dispatch([_make_result(prediction=1)]))
    assert alerts == []


def test_anomalous_result_produces_one_alert():
    dispatcher = AlertDispatcher()
    alerts = list(dispatcher.dispatch([_make_result(prediction=-1)]))
    assert len(alerts) == 1
    assert isinstance(alerts[0], Alert)


def test_mixed_results_only_produce_alerts_for_anomalies():
    results = [
        _make_result(prediction=1, command="a"),
        _make_result(prediction=-1, command="b"),
        _make_result(prediction=1, command="c"),
        _make_result(prediction=-1, command="d"),
    ]
    dispatcher = AlertDispatcher()

    alerts = list(dispatcher.dispatch(results))

    assert len(alerts) == 2
    assert [alert.command for alert in alerts] == ["b", "d"]


def test_multiple_anomalies_preserve_input_order():
    results = [
        _make_result(prediction=-1, command="first"),
        _make_result(prediction=1, command="skip-me"),
        _make_result(prediction=-1, command="second"),
        _make_result(prediction=-1, command="third"),
    ]
    dispatcher = AlertDispatcher()

    alerts = list(dispatcher.dispatch(results))

    assert [alert.command for alert in alerts] == ["first", "second", "third"]


def test_alert_builder_is_actually_used():
    fake_builder = _FakeAlertBuilder()
    dispatcher = AlertDispatcher(alert_builder=fake_builder)
    result = _make_result(prediction=-1)

    dispatcher_alerts = list(dispatcher.dispatch([result]))

    assert fake_builder.build_calls == [result]
    assert len(dispatcher_alerts) == 1


def test_empty_input_produces_no_alerts():
    dispatcher = AlertDispatcher()
    assert list(dispatcher.dispatch([])) == []


def test_generator_input_works():
    def result_generator():
        yield _make_result(prediction=1, command="a")
        yield _make_result(prediction=-1, command="b")

    dispatcher = AlertDispatcher()
    alerts = list(dispatcher.dispatch(result_generator()))

    assert len(alerts) == 1
    assert alerts[0].command == "b"


def test_original_anomaly_result_is_preserved_through_alert():
    result = _make_result(prediction=-1)
    dispatcher = AlertDispatcher()

    alerts = list(dispatcher.dispatch([result]))

    assert alerts[0].result is result


def test_original_dataset_record_remains_reachable():
    record = _make_record(command="pwd")
    result = AnomalyResult(record=record, prediction=-1, score=-0.4, is_anomaly=True)
    dispatcher = AlertDispatcher()

    alerts = list(dispatcher.dispatch([result]))

    assert alerts[0].result.record is record


def test_input_anomaly_result_objects_are_not_modified():
    result = _make_result(prediction=-1, score=-0.4)
    original_prediction = result.prediction
    original_score = result.score
    original_is_anomaly = result.is_anomaly

    list(AlertDispatcher().dispatch([result]))

    assert result.prediction == original_prediction
    assert result.score == original_score
    assert result.is_anomaly == original_is_anomaly


def test_dependency_injection_works_with_fake_alert_builder():
    fake_builder = _FakeAlertBuilder()
    dispatcher = AlertDispatcher(alert_builder=fake_builder)
    results = [_make_result(prediction=-1, command="a"), _make_result(prediction=-1, command="b")]

    alerts = list(dispatcher.dispatch(results))

    assert len(fake_builder.build_calls) == 2
    assert len(alerts) == 2


def test_no_model_retraining_or_ai_components_are_called():
    import core.runtime.alert_dispatch as dispatch_module

    source = inspect.getsource(dispatch_module)
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
        "FeatureMatrixBuilder",
        "FeatureExtractor",
        "DatasetBuilder",
        "LiveJsonLogReader",
        "CowrieAdapter",
        "IngestionPipeline",
        "LogProcessor",
        "EventEnricher",
        "sklearn",
    }
    assert imported_names.isdisjoint(forbidden_imports)


def test_anomaly_semantics_remain_unchanged():
    normal_result = _make_result(prediction=1, command="normal-one")
    anomaly_result = _make_result(prediction=-1, command="anomaly-one")

    alerts = list(AlertDispatcher().dispatch([normal_result, anomaly_result]))

    assert len(alerts) == 1
    assert alerts[0].prediction == -1
    assert alerts[0].is_anomaly is True


def test_repeated_dispatch_is_deterministic():
    results = [_make_result(prediction=-1, command="a"), _make_result(prediction=1, command="b")]

    first = list(AlertDispatcher().dispatch(results))
    second = list(AlertDispatcher().dispatch(results))

    assert first == second