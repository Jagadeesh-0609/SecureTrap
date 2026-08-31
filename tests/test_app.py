"""Isolated unit tests for core.app.main (the SecureTrap application entry point).

Uses fakes/recording factories for ModelManager, LiveJsonLogReader,
IngestionPipeline, LiveDetectionPipeline, AlertDispatcher, and
AlertStore. No real Cowrie process, no real network, no Docker, and no
real sklearn training on large data — everything here is deterministic
and fast. Uses tmp_path for all files.
"""

import ast
import inspect

import pytest

import core.app.main as app_module
from core.ai_engine.anomaly_result import AnomalyResult
from core.alert_engine.alert import Alert
from core.app.main import (
    _PrintingAlertStore,
    _load_dataset_records,
    assemble_service,
    build_parser,
    main,
)
from core.dataset_manager.builder import DatasetRecord

CSV_HEADER = (
    "timestamp,source_ip,session_id,protocol,honeypot,event_type,category,"
    "severity,command,has_command,command_length,has_url,has_ip_address,"
    "has_file_path,has_shell_metacharacters\n"
)


def _csv_row(
    timestamp="2026-08-19T18:00:22.557428Z",
    source_ip="127.0.0.1",
    session_id="ce82815367a4",
    protocol="ssh",
    honeypot="Cowrie",
    event_type="cowrie.command.input",
    category="command_execution",
    severity="low",
    command="pwd",
    has_command="True",
    command_length="3",
    has_url="False",
    has_ip_address="False",
    has_file_path="False",
    has_shell_metacharacters="False",
) -> str:
    return (
        f"{timestamp},{source_ip},{session_id},{protocol},{honeypot},{event_type},"
        f"{category},{severity},{command},{has_command},{command_length},{has_url},"
        f"{has_ip_address},{has_file_path},{has_shell_metacharacters}\n"
    )


def _write_baseline_csv(path, rows):
    path.write_text(CSV_HEADER + "".join(rows), encoding="utf-8")


def _make_alert(command="pwd", prediction=1, score=0.1) -> Alert:
    record = DatasetRecord(
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
    result = AnomalyResult(record=record, prediction=prediction, score=score, is_anomaly=(prediction == -1))
    return Alert(
        result=result,
        timestamp=record.timestamp,
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


# --- Fakes / recording factories for wiring tests -------------------------


class _RecordingFactory:
    """A callable that records every call and always returns a fixed instance."""

    def __init__(self, instance):
        self.instance = instance
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.instance


class _FakeModelManager:
    def __init__(self):
        self.fit_calls = []

    def fit(self, records):
        self.fit_calls.append(list(records))


class _FakeReader:
    """Fake reader exposing follow() -> a preset iterable of sentinels."""

    def __init__(self, items=None):
        self._items = items if items is not None else []

    def follow(self, max_polls=None):
        return iter(self._items)


class _PassthroughIngestionPipeline:
    """Fake IngestionPipeline: process() just yields whatever it was given."""

    def __init__(self, reader_iterable, adapter):
        self.reader_iterable = list(reader_iterable)
        self.adapter = adapter

    def process(self):
        return iter(self.reader_iterable)


class _PassthroughLiveDetectionPipeline:
    """Fake LiveDetectionPipeline: process() yields its input unchanged."""

    def __init__(self, log_processor, event_enricher, dataset_builder, model_manager):
        self.log_processor = log_processor
        self.event_enricher = event_enricher
        self.dataset_builder = dataset_builder
        self.model_manager = model_manager

    def process(self, validation_results):
        return iter(validation_results)


class _PassthroughAlertDispatcher:
    """Fake AlertDispatcher: dispatch() yields its input unchanged."""

    def __init__(self, alert_builder=None):
        self.alert_builder = alert_builder

    def dispatch(self, results):
        return iter(results)


class _FakeAlertStore:
    def __init__(self, path):
        self.path = path
        self.saved = []

    def save(self, alert):
        self.saved.append(alert)
        return len(self.saved)


class _SentinelAlert:
    """A minimal Alert-like stand-in exposing just what _PrintingAlertStore prints.

    Used for wiring tests that need to prove data flows end-to-end
    through the passthrough fakes without building a full
    AnomalyResult/DatasetRecord chain for every sentinel.
    """

    def __init__(self, label: str):
        self.label = label
        self.timestamp = f"ts-{label}"
        self.source_ip = "127.0.0.1"
        self.session_id = "sess"
        self.event_type = "cowrie.command.input"
        self.command = label
        self.prediction = 1
        self.score = 0.0

    def __eq__(self, other):
        return isinstance(other, _SentinelAlert) and self.label == other.label

    def __repr__(self):
        return f"_SentinelAlert({self.label!r})"


def _make_args(tmp_path, dataset=None, log=None, db=None, poll_interval=0.5):
    parser = build_parser()
    argv = []
    if dataset is not None:
        argv += ["--dataset", str(dataset)]
    if log is not None:
        argv += ["--log", str(log)]
    if db is not None:
        argv += ["--db", str(db)]
    argv += ["--poll-interval", str(poll_interval)]
    return parser.parse_args(argv)


# --- 1-3, 23: baseline CSV loading -----------------------------------------


def test_baseline_csv_is_loaded_correctly(tmp_path):
    csv_path = tmp_path / "baseline.csv"
    _write_baseline_csv(csv_path, [_csv_row(command="pwd"), _csv_row(command="ls")])

    records = _load_dataset_records(csv_path)

    assert len(records) == 2
    assert records[0].command == "pwd"
    assert records[1].command == "ls"
    assert records[0].session_id == "ce82815367a4"
    assert records[0].event_type == "cowrie.command.input"


def test_boolean_csv_fields_are_converted_correctly(tmp_path):
    csv_path = tmp_path / "baseline.csv"
    _write_baseline_csv(
        csv_path,
        [_csv_row(has_command="True", has_url="False", has_ip_address="True")],
    )

    record = _load_dataset_records(csv_path)[0]

    assert record.has_command is True
    assert record.has_url is False
    assert record.has_ip_address is True
    assert isinstance(record.has_command, bool)


def test_command_length_is_converted_to_int(tmp_path):
    csv_path = tmp_path / "baseline.csv"
    _write_baseline_csv(csv_path, [_csv_row(command_length="42")])

    record = _load_dataset_records(csv_path)[0]

    assert record.command_length == 42
    assert isinstance(record.command_length, int)


def test_current_project_files_are_not_modified_by_baseline_loading(tmp_path):
    csv_path = tmp_path / "baseline.csv"
    _write_baseline_csv(csv_path, [_csv_row()])
    original_content = csv_path.read_text(encoding="utf-8")

    _load_dataset_records(csv_path)

    assert csv_path.read_text(encoding="utf-8") == original_content


# --- 4, 5: missing/empty baseline rejected ---------------------------------


def test_empty_baseline_dataset_is_rejected(tmp_path, capsys):
    csv_path = tmp_path / "baseline.csv"
    csv_path.write_text(CSV_HEADER, encoding="utf-8")

    exit_code = main(["--dataset", str(csv_path), "--log", str(tmp_path / "cowrie.json"), "--db", str(tmp_path / "a.db")])
    output = capsys.readouterr()

    assert exit_code == 1
    assert "Error" in output.out or "Error" in output.err


def test_missing_baseline_dataset_is_rejected(tmp_path, capsys):
    missing_csv = tmp_path / "does_not_exist.csv"

    exit_code = main(["--dataset", str(missing_csv), "--log", str(tmp_path / "cowrie.json"), "--db", str(tmp_path / "a.db")])
    output = capsys.readouterr()

    assert exit_code == 1
    assert "Error" in output.out or "Error" in output.err


# --- 6, 11: ModelManager.fit() called exactly once -------------------------


def test_model_manager_fit_is_called_exactly_once(tmp_path):
    csv_path = tmp_path / "baseline.csv"
    _write_baseline_csv(csv_path, [_csv_row(command="pwd"), _csv_row(command="ls")])
    args = _make_args(tmp_path, dataset=csv_path)
    fake_manager = _FakeModelManager()

    assemble_service(
        args,
        model_manager=fake_manager,
        reader_factory=lambda *a, **k: _FakeReader(items=[]),
        ingestion_pipeline_factory=_PassthroughIngestionPipeline,
        live_detection_pipeline_factory=_PassthroughLiveDetectionPipeline,
        alert_dispatcher_factory=_PassthroughAlertDispatcher,
        alert_store_factory=_FakeAlertStore,
    )

    assert len(fake_manager.fit_calls) == 1
    assert len(fake_manager.fit_calls[0]) == 2


def test_no_second_model_fit_occurs_during_run(tmp_path):
    csv_path = tmp_path / "baseline.csv"
    _write_baseline_csv(csv_path, [_csv_row()])
    args = _make_args(tmp_path, dataset=csv_path)
    fake_manager = _FakeModelManager()

    service, ingestion_pipeline, _ = assemble_service(
        args,
        model_manager=fake_manager,
        reader_factory=lambda *a, **k: _FakeReader(items=[_SentinelAlert("1"), _SentinelAlert("2")]),
        ingestion_pipeline_factory=_PassthroughIngestionPipeline,
        live_detection_pipeline_factory=_PassthroughLiveDetectionPipeline,
        alert_dispatcher_factory=_PassthroughAlertDispatcher,
        alert_store_factory=_FakeAlertStore,
    )
    service.run(ingestion_pipeline.process())

    assert len(fake_manager.fit_calls) == 1


# --- 7, 8, 14: reader/log path, poll interval, custom args -----------------


def test_live_json_log_reader_is_constructed_with_requested_path(tmp_path):
    csv_path = tmp_path / "baseline.csv"
    _write_baseline_csv(csv_path, [_csv_row()])
    log_path = tmp_path / "cowrie.json"
    args = _make_args(tmp_path, dataset=csv_path, log=log_path)

    reader_factory = _RecordingFactory(_FakeReader(items=[]))
    assemble_service(
        args,
        model_manager=_FakeModelManager(),
        reader_factory=reader_factory,
        ingestion_pipeline_factory=_PassthroughIngestionPipeline,
        live_detection_pipeline_factory=_PassthroughLiveDetectionPipeline,
        alert_dispatcher_factory=_PassthroughAlertDispatcher,
        alert_store_factory=_FakeAlertStore,
    )

    (call_args, call_kwargs) = reader_factory.calls[0]
    assert call_args[0] == str(log_path)


def test_poll_interval_is_passed_correctly(tmp_path):
    csv_path = tmp_path / "baseline.csv"
    _write_baseline_csv(csv_path, [_csv_row()])
    args = _make_args(tmp_path, dataset=csv_path, poll_interval=1.5)

    reader_factory = _RecordingFactory(_FakeReader(items=[]))
    assemble_service(
        args,
        model_manager=_FakeModelManager(),
        reader_factory=reader_factory,
        ingestion_pipeline_factory=_PassthroughIngestionPipeline,
        live_detection_pipeline_factory=_PassthroughLiveDetectionPipeline,
        alert_dispatcher_factory=_PassthroughAlertDispatcher,
        alert_store_factory=_FakeAlertStore,
    )

    (_call_args, call_kwargs) = reader_factory.calls[0]
    assert call_kwargs["poll_interval"] == 1.5


def test_custom_dataset_log_db_arguments_are_respected(tmp_path):
    csv_path = tmp_path / "custom_baseline.csv"
    _write_baseline_csv(csv_path, [_csv_row()])
    log_path = tmp_path / "custom_cowrie.json"
    db_path = tmp_path / "custom_alerts.db"
    args = _make_args(tmp_path, dataset=csv_path, log=log_path, db=db_path)

    reader_factory = _RecordingFactory(_FakeReader(items=[]))
    alert_store_factory = _RecordingFactory(_FakeAlertStore(db_path))
    assemble_service(
        args,
        model_manager=_FakeModelManager(),
        reader_factory=reader_factory,
        ingestion_pipeline_factory=_PassthroughIngestionPipeline,
        live_detection_pipeline_factory=_PassthroughLiveDetectionPipeline,
        alert_dispatcher_factory=_PassthroughAlertDispatcher,
        alert_store_factory=alert_store_factory,
    )

    assert reader_factory.calls[0][0][0] == str(log_path)
    assert alert_store_factory.calls[0][0][0] == str(db_path)


# --- 9, 10: SecureTrapService wiring ----------------------------------------


def test_secure_trap_service_receives_the_existing_dependencies(tmp_path):
    csv_path = tmp_path / "baseline.csv"
    _write_baseline_csv(csv_path, [_csv_row()])
    args = _make_args(tmp_path, dataset=csv_path)

    fake_detection_pipeline = _PassthroughLiveDetectionPipeline(None, None, None, None)
    fake_dispatcher = _PassthroughAlertDispatcher()
    fake_store = _FakeAlertStore(args.db)

    service, _ingestion_pipeline, _baseline = assemble_service(
        args,
        model_manager=_FakeModelManager(),
        reader_factory=lambda *a, **k: _FakeReader(items=[]),
        ingestion_pipeline_factory=_PassthroughIngestionPipeline,
        live_detection_pipeline_factory=_RecordingFactory(fake_detection_pipeline),
        alert_dispatcher_factory=_RecordingFactory(fake_dispatcher),
        alert_store_factory=_RecordingFactory(fake_store),
    )

    assert service._live_detection_pipeline is fake_detection_pipeline
    assert service._alert_dispatcher is fake_dispatcher
    assert isinstance(service._alert_store, _PrintingAlertStore)
    assert service._alert_store._alert_store is fake_store


def test_secure_trap_service_run_receives_the_ingestion_output(tmp_path):
    csv_path = tmp_path / "baseline.csv"
    _write_baseline_csv(csv_path, [_csv_row()])
    args = _make_args(tmp_path, dataset=csv_path)
    fake_store = _FakeAlertStore(args.db)
    sentinel_a = _SentinelAlert("a")
    sentinel_b = _SentinelAlert("b")

    service, ingestion_pipeline, _baseline = assemble_service(
        args,
        model_manager=_FakeModelManager(),
        reader_factory=lambda *a, **k: _FakeReader(items=[sentinel_a, sentinel_b]),
        ingestion_pipeline_factory=_PassthroughIngestionPipeline,
        live_detection_pipeline_factory=_PassthroughLiveDetectionPipeline,
        alert_dispatcher_factory=_PassthroughAlertDispatcher,
        alert_store_factory=lambda *a, **k: fake_store,
    )

    count = service.run(ingestion_pipeline.process())

    assert count == 2
    assert fake_store.saved == [sentinel_a, sentinel_b]


# --- 12, 15: KeyboardInterrupt and unrelated runtime errors ----------------


def test_ctrl_c_exits_cleanly(tmp_path, capsys, monkeypatch):
    csv_path = tmp_path / "baseline.csv"
    _write_baseline_csv(csv_path, [_csv_row()])

    class _InterruptingService:
        def run(self, validation_results):
            raise KeyboardInterrupt

    monkeypatch.setattr(
        app_module,
        "assemble_service",
        lambda args: (_InterruptingService(), _PassthroughIngestionPipeline([], None), [object()]),
    )

    exit_code = main(["--dataset", str(csv_path)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "SecureTrap monitoring stopped." in output


def test_runtime_errors_are_not_silently_swallowed(tmp_path, monkeypatch):
    csv_path = tmp_path / "baseline.csv"
    _write_baseline_csv(csv_path, [_csv_row()])

    class _FailingService:
        def run(self, validation_results):
            raise RuntimeError("boom")

    monkeypatch.setattr(
        app_module,
        "assemble_service",
        lambda args: (_FailingService(), _PassthroughIngestionPipeline([], None), [object()]),
    )

    with pytest.raises(RuntimeError):
        main(["--dataset", str(csv_path)])


# --- 13: invalid poll interval ----------------------------------------------


def test_invalid_poll_interval_is_rejected(tmp_path):
    csv_path = tmp_path / "baseline.csv"
    _write_baseline_csv(csv_path, [_csv_row()])

    with pytest.raises(SystemExit):
        main(["--dataset", str(csv_path), "--poll-interval", "0"])

    with pytest.raises(SystemExit):
        main(["--dataset", str(csv_path), "--poll-interval", "-1"])


# --- 16, 17, 18, 19: static dependency/behavior checks ----------------------


def _imported_names(source: str):
    tree = ast.parse(source)
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
                if alias.asname:
                    names.add(alias.asname)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module.split(".")[0])
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


def test_no_pandas_dependency_is_introduced():
    source = inspect.getsource(app_module)
    assert "pandas" not in _imported_names(source)


def test_no_sql_is_written_in_main_py():
    source = inspect.getsource(app_module)
    assert "sqlite3" not in _imported_names(source)


def test_no_legacy_imports_are_introduced():
    source = inspect.getsource(app_module)
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert not node.module.startswith("legacy")
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("legacy")

    names = _imported_names(source)
    assert "CountVectorizer" not in names
    assert "MultinomialNB" not in names


def test_no_direct_anomaly_filtering_is_implemented_in_main_py():
    source = inspect.getsource(app_module)
    tree = ast.parse(source)

    is_anomaly_accesses = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "is_anomaly"
    ]
    assert is_anomaly_accesses == []


# --- 20: startup configuration reporting ------------------------------------


def test_startup_configuration_is_reported_clearly(tmp_path, capsys, monkeypatch):
    csv_path = tmp_path / "baseline.csv"
    _write_baseline_csv(csv_path, [_csv_row(), _csv_row(command="ls")])
    log_path = tmp_path / "cowrie.json"
    db_path = tmp_path / "alerts.db"

    class _NoOpService:
        def run(self, validation_results):
            list(validation_results)
            return 0

    monkeypatch.setattr(
        app_module,
        "assemble_service",
        lambda args: (_NoOpService(), _PassthroughIngestionPipeline([], None), [object(), object()]),
    )

    main(["--dataset", str(csv_path), "--log", str(log_path), "--db", str(db_path), "--poll-interval", "0.5"])
    output = capsys.readouterr().out

    assert "Baseline records: 2" in output
    assert f"Log file: {log_path}" in output
    assert f"Alert database: {db_path}" in output
    assert "Poll interval: 0.5" in output


# --- 21, 22: _PrintingAlertStore behavior -----------------------------------


def test_alert_printing_only_occurs_after_successful_save(capsys):
    fake_store = _FakeAlertStore(path="unused")
    printing_store = _PrintingAlertStore(fake_store)
    alert = _make_alert(command="pwd", prediction=-1, score=-0.4)

    alert_id = printing_store.save(alert)
    output = capsys.readouterr().out

    assert alert_id == 1
    assert fake_store.saved == [alert]
    assert "ALERT" in output
    assert "pwd" in output


def test_alert_store_save_failure_propagates(capsys):
    class _FailingAlertStore:
        def save(self, alert):
            raise RuntimeError("disk full")

    printing_store = _PrintingAlertStore(_FailingAlertStore())
    alert = _make_alert()

    with pytest.raises(RuntimeError):
        printing_store.save(alert)

    output = capsys.readouterr().out
    assert output == ""