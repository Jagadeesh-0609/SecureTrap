"""Isolated unit tests for SecureTrapService.

Uses simple fake collaborators throughout — no real Cowrie, no
Docker, no network, no sklearn, and no real sqlite files (AlertStore
itself is faked here, so tmp_path isn't even needed).
"""

import ast
import inspect

import pytest

from core.ai_engine.anomaly_result import AnomalyResult
from core.alert_engine.alert import Alert
from core.dataset_manager.builder import DatasetRecord
from core.event_engine.event import AttackEvent
from core.event_engine.validator import ValidationResult
from core.runtime.service import SecureTrapService


def _make_attack_event(command: str = "pwd") -> AttackEvent:
    return AttackEvent(
        timestamp="2026-08-19T18:00:22.557428Z",
        source_ip="127.0.0.1",
        session_id="ce82815367a4",
        protocol="ssh",
        command=command,
        event_type="cowrie.command.input",
        honeypot="Cowrie",
    )


def _valid_result(command: str = "pwd") -> ValidationResult:
    return ValidationResult(valid=True, event=_make_attack_event(command=command), errors=[])


def _make_record(command: str = "pwd") -> DatasetRecord:
    return DatasetRecord(
        timestamp="2026-08-19T18:00:22.557428Z",
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


def _make_anomaly_result(prediction: int = 1, score: float = 0.1, command: str = "pwd") -> AnomalyResult:
    return AnomalyResult(
        record=_make_record(command=command),
        prediction=prediction,
        score=score,
        is_anomaly=(prediction == -1),
    )


def _make_alert(result: AnomalyResult) -> Alert:
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


class _FakeLiveDetectionPipeline:
    """Fake LiveDetectionPipeline: records input, yields controlled results."""

    def __init__(self, results=None):
        self.received_validation_results = None
        self._results = results if results is not None else []

    def process(self, validation_results):
        self.received_validation_results = list(validation_results)
        for result in self._results:
            yield result


class _FakeAlertDispatcher:
    """Fake AlertDispatcher: records input, yields alerts for chosen results.

    `alerts_by_result_id` maps id(anomaly_result) -> Alert, since
    AnomalyResult (a plain, non-frozen dataclass) isn't hashable.
    """

    def __init__(self, alerts_by_result_id=None):
        self.received_results = []
        self._alerts_by_result_id = alerts_by_result_id if alerts_by_result_id is not None else {}

    def dispatch(self, results):
        for result in results:
            self.received_results.append(result)
            alert = self._alerts_by_result_id.get(id(result))
            if alert is not None:
                yield alert


class _FakeAlertStore:
    """Fake AlertStore: records saved alerts, returns fake IDs."""

    def __init__(self, fail_on_save: bool = False):
        self.saved_alerts = []
        self._next_id = 1
        self.fail_on_save = fail_on_save

    def save(self, alert):
        if self.fail_on_save:
            raise RuntimeError("Simulated AlertStore failure")
        self.saved_alerts.append(alert)
        alert_id = self._next_id
        self._next_id += 1
        return alert_id


def test_empty_input_returns_zero():
    service = SecureTrapService(
        live_detection_pipeline=_FakeLiveDetectionPipeline(results=[]),
        alert_dispatcher=_FakeAlertDispatcher(),
        alert_store=_FakeAlertStore(),
    )

    assert service.run([]) == 0


def test_one_normal_result_persists_zero_alerts():
    normal_result = _make_anomaly_result(prediction=1)
    store = _FakeAlertStore()
    service = SecureTrapService(
        live_detection_pipeline=_FakeLiveDetectionPipeline(results=[normal_result]),
        alert_dispatcher=_FakeAlertDispatcher(alerts_by_result_id={}),
        alert_store=store,
    )

    count = service.run([_valid_result()])

    assert count == 0
    assert store.saved_alerts == []


def test_one_anomaly_result_persists_one_alert():
    anomaly_result = _make_anomaly_result(prediction=-1)
    alert = _make_alert(anomaly_result)
    store = _FakeAlertStore()
    service = SecureTrapService(
        live_detection_pipeline=_FakeLiveDetectionPipeline(results=[anomaly_result]),
        alert_dispatcher=_FakeAlertDispatcher(alerts_by_result_id={id(anomaly_result): alert}),
        alert_store=store,
    )

    count = service.run([_valid_result()])

    assert count == 1
    assert store.saved_alerts == [alert]


def test_mixed_results_persist_only_anomalies():
    normal_result = _make_anomaly_result(prediction=1, command="a")
    anomaly_result = _make_anomaly_result(prediction=-1, command="b")
    alert = _make_alert(anomaly_result)
    store = _FakeAlertStore()
    service = SecureTrapService(
        live_detection_pipeline=_FakeLiveDetectionPipeline(results=[normal_result, anomaly_result]),
        alert_dispatcher=_FakeAlertDispatcher(alerts_by_result_id={id(anomaly_result): alert}),
        alert_store=store,
    )

    count = service.run([_valid_result(), _valid_result()])

    assert count == 1
    assert store.saved_alerts == [alert]


def test_multiple_anomalies_preserve_order():
    result_a = _make_anomaly_result(prediction=-1, command="a")
    result_b = _make_anomaly_result(prediction=-1, command="b")
    alert_a = _make_alert(result_a)
    alert_b = _make_alert(result_b)
    store = _FakeAlertStore()
    service = SecureTrapService(
        live_detection_pipeline=_FakeLiveDetectionPipeline(results=[result_a, result_b]),
        alert_dispatcher=_FakeAlertDispatcher(
            alerts_by_result_id={id(result_a): alert_a, id(result_b): alert_b}
        ),
        alert_store=store,
    )

    service.run([_valid_result(), _valid_result()])

    assert store.saved_alerts == [alert_a, alert_b]


def test_alert_store_save_is_actually_used():
    anomaly_result = _make_anomaly_result(prediction=-1)
    alert = _make_alert(anomaly_result)
    store = _FakeAlertStore()
    service = SecureTrapService(
        live_detection_pipeline=_FakeLiveDetectionPipeline(results=[anomaly_result]),
        alert_dispatcher=_FakeAlertDispatcher(alerts_by_result_id={id(anomaly_result): alert}),
        alert_store=store,
    )

    service.run([_valid_result()])

    assert len(store.saved_alerts) == 1


def test_alert_dispatcher_is_actually_used():
    anomaly_result = _make_anomaly_result(prediction=-1)
    alert = _make_alert(anomaly_result)
    dispatcher = _FakeAlertDispatcher(alerts_by_result_id={id(anomaly_result): alert})
    service = SecureTrapService(
        live_detection_pipeline=_FakeLiveDetectionPipeline(results=[anomaly_result]),
        alert_dispatcher=dispatcher,
        alert_store=_FakeAlertStore(),
    )

    service.run([_valid_result()])

    assert dispatcher.received_results == [anomaly_result]


def test_live_detection_pipeline_is_actually_used():
    pipeline = _FakeLiveDetectionPipeline(results=[])
    service = SecureTrapService(
        live_detection_pipeline=pipeline,
        alert_dispatcher=_FakeAlertDispatcher(),
        alert_store=_FakeAlertStore(),
    )
    validation_results = [_valid_result(), _valid_result()]

    service.run(validation_results)

    assert pipeline.received_validation_results == validation_results


def test_model_training_is_never_triggered_by_the_service():
    import core.runtime.service as service_module

    source = inspect.getsource(service_module)
    tree = ast.parse(source)

    fit_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "fit"
    ]
    assert fit_calls == []


def test_persisted_alert_count_matches_returned_count():
    result_a = _make_anomaly_result(prediction=-1, command="a")
    result_b = _make_anomaly_result(prediction=-1, command="b")
    alert_a = _make_alert(result_a)
    alert_b = _make_alert(result_b)
    store = _FakeAlertStore()
    service = SecureTrapService(
        live_detection_pipeline=_FakeLiveDetectionPipeline(results=[result_a, result_b]),
        alert_dispatcher=_FakeAlertDispatcher(
            alerts_by_result_id={id(result_a): alert_a, id(result_b): alert_b}
        ),
        alert_store=store,
    )

    count = service.run([_valid_result(), _valid_result()])

    assert count == len(store.saved_alerts)


def test_generator_input_works():
    anomaly_result = _make_anomaly_result(prediction=-1)
    alert = _make_alert(anomaly_result)
    store = _FakeAlertStore()
    service = SecureTrapService(
        live_detection_pipeline=_FakeLiveDetectionPipeline(results=[anomaly_result]),
        alert_dispatcher=_FakeAlertDispatcher(alerts_by_result_id={id(anomaly_result): alert}),
        alert_store=store,
    )

    def result_generator():
        yield _valid_result()

    count = service.run(result_generator())

    assert count == 1


def test_original_alert_and_anomaly_result_are_not_modified():
    anomaly_result = _make_anomaly_result(prediction=-1, score=-0.5)
    alert = _make_alert(anomaly_result)
    original_prediction = anomaly_result.prediction
    original_score = anomaly_result.score
    original_alert_command = alert.command
    service = SecureTrapService(
        live_detection_pipeline=_FakeLiveDetectionPipeline(results=[anomaly_result]),
        alert_dispatcher=_FakeAlertDispatcher(alerts_by_result_id={id(anomaly_result): alert}),
        alert_store=_FakeAlertStore(),
    )

    service.run([_valid_result()])

    assert anomaly_result.prediction == original_prediction
    assert anomaly_result.score == original_score
    assert alert.command == original_alert_command


def test_runtime_error_from_unfitted_pipeline_propagates():
    class _RaisingLiveDetectionPipeline:
        def process(self, validation_results):
            list(validation_results)
            raise RuntimeError(
                "ModelManager must be fitted with fit() before calling predict()."
            )

    service = SecureTrapService(
        live_detection_pipeline=_RaisingLiveDetectionPipeline(),
        alert_dispatcher=_FakeAlertDispatcher(),
        alert_store=_FakeAlertStore(),
    )

    with pytest.raises(RuntimeError):
        service.run([_valid_result()])


def test_multiple_events_are_processed_to_exhaustion():
    results = [
        _make_anomaly_result(prediction=1, command="a"),
        _make_anomaly_result(prediction=-1, command="b"),
        _make_anomaly_result(prediction=1, command="c"),
        _make_anomaly_result(prediction=-1, command="d"),
        _make_anomaly_result(prediction=1, command="e"),
    ]
    alerts_by_id = {id(result): _make_alert(result) for result in results if result.is_anomaly}
    store = _FakeAlertStore()
    service = SecureTrapService(
        live_detection_pipeline=_FakeLiveDetectionPipeline(results=results),
        alert_dispatcher=_FakeAlertDispatcher(alerts_by_result_id=alerts_by_id),
        alert_store=store,
    )

    validation_results = [_valid_result() for _ in range(5)]
    count = service.run(validation_results)

    assert count == 2
    assert len(store.saved_alerts) == 2


def test_dependency_injection_works_with_fakes():
    anomaly_result = _make_anomaly_result(prediction=-1)
    alert = _make_alert(anomaly_result)
    pipeline = _FakeLiveDetectionPipeline(results=[anomaly_result])
    dispatcher = _FakeAlertDispatcher(alerts_by_result_id={id(anomaly_result): alert})
    store = _FakeAlertStore()

    service = SecureTrapService(
        live_detection_pipeline=pipeline,
        alert_dispatcher=dispatcher,
        alert_store=store,
    )
    validation_results = [_valid_result()]
    count = service.run(validation_results)

    assert pipeline.received_validation_results == validation_results
    assert dispatcher.received_results == [anomaly_result]
    assert store.saved_alerts == [alert]
    assert count == 1


def test_no_cowrie_log_or_ai_model_dependencies_are_imported_directly():
    import core.runtime.service as service_module

    source = inspect.getsource(service_module)
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
        "AnomalyDetector",
        "FeatureExtractor",
        "FeatureMatrixBuilder",
        "AlertBuilder",
        "sklearn",
    }
    assert imported_names.isdisjoint(forbidden_imports)