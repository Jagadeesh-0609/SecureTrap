"""Isolated unit tests for core.app.logging_config and its integration
with core.app.config / core.app.main.

An autouse fixture resets the "securetrap" logger's handlers after
every test in this file, so nothing here leaks state into other test
files (e.g. tests/test_app.py, which never calls configure_logging()
itself).
"""

import ast
import inspect
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

import pytest

from core.ai_engine.anomaly_result import AnomalyResult
from core.alert_engine.alert import Alert
from core.app.config import DEFAULT_LOG_FILE_PATH, ENV_LOG_FILE, load_config
from core.app.logging_config import LOGGER_NAME, configure_logging
from core.dataset_manager.builder import DatasetRecord


@pytest.fixture(autouse=True)
def _reset_securetrap_logger():
    logger = logging.getLogger(LOGGER_NAME)
    original_handlers = list(logger.handlers)
    original_level = logger.level
    original_propagate = logger.propagate

    yield

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    for handler in original_handlers:
        logger.addHandler(handler)
    logger.setLevel(original_level)
    logger.propagate = original_propagate


def _read_log(path) -> str:
    return Path(path).read_text(encoding="utf-8")


def _make_alert(command: str = "pwd", prediction: int = 1, score: float = 0.1) -> Alert:
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


# --- 1-4: AppConfig.log_file precedence / validation ------------------------


def test_default_log_file_path():
    config = load_config(env={})
    assert config.log_file == Path(DEFAULT_LOG_FILE_PATH)


def test_environment_override_for_log_file():
    config = load_config(env={ENV_LOG_FILE: "/custom/securetrap.log"})
    assert config.log_file == Path("/custom/securetrap.log")


def test_cli_over_environment_precedence_for_log_file():
    config = load_config(
        log_file="/explicit/securetrap.log",
        env={ENV_LOG_FILE: "/from-env/securetrap.log"},
    )
    assert config.log_file == Path("/explicit/securetrap.log")


def test_invalid_log_file_configuration_is_rejected():
    with pytest.raises(ValueError):
        load_config(log_file="", env={})


# --- 5: parent directory creation -------------------------------------------


def test_logging_configuration_creates_parent_directory(tmp_path):
    log_file = tmp_path / "nested" / "logs" / "securetrap.log"
    assert not log_file.parent.exists()

    configure_logging(log_file)

    assert log_file.parent.exists()


# --- 6, 7, 8: file logging, console logging, rotating handler ---------------


def test_file_logging_works(tmp_path):
    log_file = tmp_path / "securetrap.log"
    logger = configure_logging(log_file)

    logger.info("hello from test_file_logging_works")
    for handler in logger.handlers:
        handler.flush()

    assert "hello from test_file_logging_works" in _read_log(log_file)


def test_console_logging_works(tmp_path, capsys):
    log_file = tmp_path / "securetrap.log"
    logger = configure_logging(log_file)

    logger.info("hello from test_console_logging_works")
    for handler in logger.handlers:
        handler.flush()

    output = capsys.readouterr()
    assert "hello from test_console_logging_works" in (output.out + output.err)


def test_rotating_handler_is_used(tmp_path):
    log_file = tmp_path / "securetrap.log"
    logger = configure_logging(log_file)

    file_handlers = [h for h in logger.handlers if isinstance(h, RotatingFileHandler)]
    assert len(file_handlers) == 1


# --- 9: repeated configuration does not duplicate handlers ------------------


def test_repeated_configuration_does_not_duplicate_handlers(tmp_path):
    log_file = tmp_path / "securetrap.log"

    configure_logging(log_file)
    configure_logging(log_file)
    logger = configure_logging(log_file)

    assert len(logger.handlers) == 2  # exactly one file handler + one console handler


# --- 10, 11: startup/shutdown logging via main() ----------------------------


def test_startup_is_logged(tmp_path, monkeypatch):
    import core.app.main as app_module

    log_file = tmp_path / "securetrap.log"

    class _NoOpService:
        def run(self, validation_results):
            list(validation_results)
            return 0

    class _NoOpIngestion:
        def process(self):
            return iter([])

    monkeypatch.setattr(
        app_module,
        "assemble_service",
        lambda args: (_NoOpService(), _NoOpIngestion(), [object(), object()]),
    )

    app_module.main(
        ["--dataset", "unused.csv", "--log-file", str(log_file), "--db", str(tmp_path / "alerts.db")]
    )

    for handler in logging.getLogger(LOGGER_NAME).handlers:
        handler.flush()

    log_content = _read_log(log_file)
    # "Application startup" and "successful initialization" are two
    # distinct logged events: the first before assembly is attempted,
    # the second only after it succeeds.
    assert "SecureTrap application starting." in log_content
    assert "SecureTrap initialization successful." in log_content
    assert "baseline_records=2" in log_content


def test_successful_initialization_is_logged_after_startup(tmp_path, monkeypatch):
    import core.app.main as app_module

    log_file = tmp_path / "securetrap.log"

    class _NoOpService:
        def run(self, validation_results):
            list(validation_results)
            return 0

    class _NoOpIngestion:
        def process(self):
            return iter([])

    monkeypatch.setattr(
        app_module,
        "assemble_service",
        lambda args: (_NoOpService(), _NoOpIngestion(), [object(), object(), object()]),
    )

    app_module.main(
        ["--dataset", "unused.csv", "--log-file", str(log_file), "--db", str(tmp_path / "alerts.db")]
    )

    for handler in logging.getLogger(LOGGER_NAME).handlers:
        handler.flush()

    log_content = _read_log(log_file)
    startup_index = log_content.index("SecureTrap application starting.")
    init_index = log_content.index("SecureTrap initialization successful.")

    # Startup is logged strictly before successful initialization.
    assert startup_index < init_index
    assert "baseline_records=3" in log_content


def test_shutdown_is_logged(tmp_path, monkeypatch):
    import core.app.main as app_module

    log_file = tmp_path / "securetrap.log"

    class _InterruptingService:
        def run(self, validation_results):
            raise KeyboardInterrupt

    class _NoOpIngestion:
        def process(self):
            return iter([])

    monkeypatch.setattr(
        app_module,
        "assemble_service",
        lambda args: (_InterruptingService(), _NoOpIngestion(), [object()]),
    )

    exit_code = app_module.main(
        ["--dataset", "unused.csv", "--log-file", str(log_file), "--db", str(tmp_path / "alerts.db")]
    )

    for handler in logging.getLogger(LOGGER_NAME).handlers:
        handler.flush()

    assert exit_code == 0
    assert "SecureTrap monitoring stopped." in _read_log(log_file)


def test_runtime_exceptions_are_logged_and_reraised(tmp_path, monkeypatch):
    import core.app.main as app_module

    log_file = tmp_path / "securetrap.log"

    class _FailingService:
        def run(self, validation_results):
            raise RuntimeError("boom")

    class _NoOpIngestion:
        def process(self):
            return iter([])

    monkeypatch.setattr(
        app_module,
        "assemble_service",
        lambda args: (_FailingService(), _NoOpIngestion(), [object()]),
    )

    with pytest.raises(RuntimeError):
        app_module.main(
            ["--dataset", "unused.csv", "--log-file", str(log_file), "--db", str(tmp_path / "alerts.db")]
        )

    for handler in logging.getLogger(LOGGER_NAME).handlers:
        handler.flush()

    log_content = _read_log(log_file)
    assert "boom" in log_content
    assert "RuntimeError" in log_content


# --- 12, 13: alert persistence logging --------------------------------------


def test_alert_persistence_is_logged_only_after_successful_save(tmp_path):
    from core.app.main import _PrintingAlertStore

    log_file = tmp_path / "securetrap.log"
    configure_logging(log_file)

    class _SucceedingStore:
        def save(self, alert):
            return 1

    printing_store = _PrintingAlertStore(_SucceedingStore())
    alert = _make_alert(command="pwd", prediction=-1, score=-0.4)

    printing_store.save(alert)

    for handler in logging.getLogger(LOGGER_NAME).handlers:
        handler.flush()

    log_content = _read_log(log_file)
    assert "ALERT" in log_content
    assert f"timestamp={alert.timestamp}" in log_content
    assert f"source_ip={alert.source_ip}" in log_content
    assert f"session={alert.session_id}" in log_content
    assert f"event={alert.event_type}" in log_content
    assert "prediction=-1" in log_content
    assert "score=-0.4" in log_content
    # The raw command must never reach the application log, even
    # though it's fine for it to appear in the terminal ALERT print.
    assert "pwd" not in log_content
    assert "command=" not in log_content


def test_save_failures_do_not_produce_a_false_success_log(tmp_path):
    from core.app.main import _PrintingAlertStore

    log_file = tmp_path / "securetrap.log"
    configure_logging(log_file)

    class _FailingStore:
        def save(self, alert):
            raise RuntimeError("disk full")

    printing_store = _PrintingAlertStore(_FailingStore())
    alert = _make_alert(command="pwd")

    with pytest.raises(RuntimeError):
        printing_store.save(alert)

    for handler in logging.getLogger(LOGGER_NAME).handlers:
        handler.flush()

    log_content = _read_log(log_file)
    assert "pwd" not in log_content
    assert "ALERT" not in log_content


# --- 15, 16: dependency checks -----------------------------------------------


def _imported_top_level_names(source: str):
    tree = ast.parse(source)
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module.split(".")[0])
    return names


def test_no_model_or_honeypot_dependencies_in_logging_config():
    import core.app.logging_config as logging_config_module

    source = inspect.getsource(logging_config_module)
    names = _imported_top_level_names(source)

    forbidden = {
        "ModelManager",
        "AnomalyDetector",
        "FeatureExtractor",
        "FeatureMatrixBuilder",
        "LiveDetectionPipeline",
        "SecureTrapService",
        "AlertDispatcher",
        "AlertStore",
        "CowrieAdapter",
        "LogReader",
        "IngestionPipeline",
        "LogProcessor",
        "EventEnricher",
        "DatasetBuilder",
        "sklearn",
    }
    assert names.isdisjoint(forbidden)


def test_no_third_party_logging_dependency():
    import core.app.logging_config as logging_config_module

    source = inspect.getsource(logging_config_module)
    names = _imported_top_level_names(source)

    third_party_logging_packages = {"loguru", "structlog", "colorlog", "coloredlogs"}
    assert names.isdisjoint(third_party_logging_packages)
    # Standard library only.
    assert names <= {"logging", "pathlib", "typing"}