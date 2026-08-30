"""Isolated unit tests for the SecureTrap CLI.

Invokes core.cli.main.main() directly (no subprocess/shell calls).
Uses tmp_path for all databases. Requires no Cowrie, no Docker, no
network, no sklearn, and no other external services.
"""

import ast
import inspect

from core.ai_engine.anomaly_result import AnomalyResult
from core.alert_engine.alert import Alert
from core.alert_engine.alert_store import AlertStore
from core.cli.main import main
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


def test_summary_on_empty_database(tmp_path, capsys):
    db_path = tmp_path / "alerts.db"

    exit_code = main(["summary", "--db", str(db_path)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Total alerts: 0" in output
    assert "Anomaly alerts: 0" in output
    assert "Normal alerts: 0" in output
    assert "Latest timestamp: None" in output


def test_summary_with_one_anomalous_alert(tmp_path, capsys):
    db_path = tmp_path / "alerts.db"
    AlertStore(db_path).save(_make_alert(prediction=-1))

    exit_code = main(["summary", "--db", str(db_path)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Total alerts: 1" in output
    assert "Anomaly alerts: 1" in output
    assert "Normal alerts: 0" in output


def test_summary_with_mixed_alerts(tmp_path, capsys):
    db_path = tmp_path / "alerts.db"
    store = AlertStore(db_path)
    store.save(_make_alert(prediction=1, command="a"))
    store.save(_make_alert(prediction=-1, command="b"))
    store.save(_make_alert(prediction=1, command="c"))

    exit_code = main(["summary", "--db", str(db_path)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Total alerts: 3" in output
    assert "Anomaly alerts: 1" in output
    assert "Normal alerts: 2" in output


def test_alerts_command_on_empty_database(tmp_path, capsys):
    db_path = tmp_path / "alerts.db"

    exit_code = main(["alerts", "--db", str(db_path)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "No alerts found." in output


def test_alerts_command_shows_stored_alert(tmp_path, capsys):
    db_path = tmp_path / "alerts.db"
    AlertStore(db_path).save(_make_alert(command="pwd", prediction=-1, score=-0.42))

    exit_code = main(["alerts", "--db", str(db_path)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "pwd" in output


def test_limit_is_respected(tmp_path, capsys):
    db_path = tmp_path / "alerts.db"
    store = AlertStore(db_path)
    for command in ["a", "b", "c", "d", "e"]:
        store.save(_make_alert(command=command))

    exit_code = main(["alerts", "--db", str(db_path), "--limit", "2"])
    output = capsys.readouterr().out

    assert exit_code == 0
    lines = [line for line in output.splitlines() if line.strip()]
    assert len(lines) == 2


def test_invalid_limit_returns_an_error(tmp_path, capsys):
    db_path = tmp_path / "alerts.db"
    AlertStore(db_path).save(_make_alert())

    exit_code = main(["alerts", "--db", str(db_path), "--limit", "0"])
    output = capsys.readouterr()

    assert exit_code != 0
    assert "Error" in output.out or "Error" in output.err


def test_custom_db_path_works(tmp_path, capsys):
    db_path = tmp_path / "custom" / "location" / "alerts.db"
    AlertStore(db_path).save(_make_alert(command="custom-path-test"))

    exit_code = main(["alerts", "--db", str(db_path)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "custom-path-test" in output


def test_cli_does_not_modify_database_when_only_reading(tmp_path, capsys):
    db_path = tmp_path / "alerts.db"
    store = AlertStore(db_path)
    store.save(_make_alert(command="pwd"))

    main(["summary", "--db", str(db_path)])
    main(["alerts", "--db", str(db_path)])
    capsys.readouterr()

    assert store.count() == 1


def test_alert_ordering_remains_newest_first(tmp_path, capsys):
    db_path = tmp_path / "alerts.db"
    store = AlertStore(db_path)
    store.save(_make_alert(command="first"))
    store.save(_make_alert(command="second"))
    store.save(_make_alert(command="third"))

    main(["alerts", "--db", str(db_path)])
    output = capsys.readouterr().out

    first_index = output.index("first")
    second_index = output.index("second")
    third_index = output.index("third")
    assert third_index < second_index < first_index


def test_command_strings_are_shown_correctly(tmp_path, capsys):
    db_path = tmp_path / "alerts.db"
    AlertStore(db_path).save(_make_alert(command="echo http://1.2.3.4"))

    main(["alerts", "--db", str(db_path)])
    output = capsys.readouterr().out

    assert "echo http://1.2.3.4" in output


def test_score_and_prediction_are_shown(tmp_path, capsys):
    db_path = tmp_path / "alerts.db"
    AlertStore(db_path).save(_make_alert(prediction=-1, score=-0.2116))

    main(["alerts", "--db", str(db_path)])
    output = capsys.readouterr().out

    assert "prediction=-1" in output
    assert "score=-0.2116" in output


def test_no_attack_or_benign_labels_are_printed(tmp_path, capsys):
    db_path = tmp_path / "alerts.db"
    store = AlertStore(db_path)
    store.save(_make_alert(prediction=1))
    store.save(_make_alert(prediction=-1))

    main(["summary", "--db", str(db_path)])
    main(["alerts", "--db", str(db_path)])
    output = capsys.readouterr().out.lower()

    forbidden_terms = ["attack", "benign", "malware", "threat level", "confidence"]
    for term in forbidden_terms:
        assert term not in output


def test_cli_uses_alert_reporter_rather_than_direct_sql():
    import core.cli.main as cli_module

    source = inspect.getsource(cli_module)
    tree = ast.parse(source)

    imported_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_names.add(node.module.split(".")[0])

    assert "sqlite3" not in imported_names
    assert "AlertReporter" in source


def test_cli_has_no_model_or_honeypot_dependencies():
    import core.cli.main as cli_module

    source = inspect.getsource(cli_module)
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
        "SecureTrapService",
        "AlertDispatcher",
        "CowrieAdapter",
        "LogReader",
        "IngestionPipeline",
        "LogProcessor",
        "EventEnricher",
        "DatasetBuilder",
        "sklearn",
    }
    assert imported_names.isdisjoint(forbidden_imports)


def test_repeated_read_commands_are_deterministic(tmp_path, capsys):
    db_path = tmp_path / "alerts.db"
    AlertStore(db_path).save(_make_alert(prediction=-1, command="pwd"))

    main(["summary", "--db", str(db_path)])
    first_output = capsys.readouterr().out

    main(["summary", "--db", str(db_path)])
    second_output = capsys.readouterr().out

    assert first_output == second_output