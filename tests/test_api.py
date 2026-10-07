"""Isolated tests for the SecureTrap FastAPI application.

Every test wires AlertStore through FastAPI's dependency override
mechanism, pointed at a temporary database — none of these tests ever
touch a real SecureTrap database, a real Cowrie log, or the network.
No fixture here constructs a reader, an adapter, or anything from
core.ai_engine; if the API accidentally required any of that, these
tests would fail to even set up.
"""

import ast
import importlib
import inspect

import pytest
from fastapi.testclient import TestClient

from core.ai_engine.anomaly_result import AnomalyResult
from core.alert_engine.alert import Alert
from core.alert_engine.alert_store import AlertStore
from api.app import create_app
from api.dependencies import get_alert_store
from core.dataset_manager.builder import DatasetRecord


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


@pytest.fixture
def api(tmp_path):
    """A TestClient wired to an isolated, temporary AlertStore.

    Used without entering FastAPI's startup/shutdown lifespan (this
    app defines none), so no logging or other side effect fires
    beyond what each test does explicitly.
    """
    app = create_app()
    store = AlertStore(tmp_path / "alerts.db")
    app.dependency_overrides[get_alert_store] = lambda: store
    client = TestClient(app)
    yield client, store
    app.dependency_overrides.clear()


def test_health_returns_200(api):
    client, _ = api
    response = client.get("/health")
    assert response.status_code == 200


def test_health_response_has_expected_status(api):
    client, _ = api
    response = client.get("/health")
    assert response.json() == {"status": "ok"}


def test_alerts_endpoint_returns_200(api):
    client, _ = api
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200


def test_alerts_response_is_json_serializable_list(api):
    client, store = api
    store.save(_make_alert(command="pwd"))

    response = client.get("/api/v1/alerts")
    payload = response.json()

    assert isinstance(payload, list)
    assert len(payload) == 1


def test_alert_store_integration_via_dependency_injection(api):
    client, store = api
    store.save(_make_alert(command="whoami", prediction=-1, score=-0.4))

    response = client.get("/api/v1/alerts")
    payload = response.json()

    assert len(payload) == 1
    assert payload[0]["command"] == "whoami"
    assert payload[0]["prediction"] == -1
    assert payload[0]["is_anomaly"] is True
    assert payload[0]["score"] == -0.4


def test_empty_alert_store_returns_valid_empty_response(api):
    client, _ = api
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    assert response.json() == []


def test_api_does_not_require_cowrie(api):
    # No LiveJsonLogReader, no CowrieAdapter, no live log file exists
    # anywhere in this fixture — if the API required Cowrie to be
    # running, this would fail.
    client, _ = api
    response = client.get("/health")
    assert response.status_code == 200


def test_alerts_limit_query_parameter_is_respected(api):
    client, store = api
    for i in range(5):
        store.save(_make_alert(command=f"cmd-{i}"))

    response = client.get("/api/v1/alerts", params={"limit": 2})
    payload = response.json()

    assert len(payload) == 2
    # AlertStore.list_recent() is newest-first.
    assert payload[0]["command"] == "cmd-4"
    assert payload[1]["command"] == "cmd-3"


def test_invalid_limit_returns_422(api):
    client, _ = api
    response = client.get("/api/v1/alerts", params={"limit": 0})
    assert response.status_code == 422


def test_alert_response_fields_match_alert_model_exactly(api):
    client, store = api
    store.save(_make_alert(command="pwd", prediction=-1, score=-0.33))

    response = client.get("/api/v1/alerts")
    payload = response.json()[0]

    assert set(payload.keys()) == {
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


def test_existing_alert_store_behavior_remains_intact(tmp_path):
    # AlertStore itself was not modified by this task — save(),
    # get_by_id(), list_recent(), and count() all still behave exactly
    # as before, independent of the API layer.
    store = AlertStore(tmp_path / "alerts.db")
    alert_id = store.save(_make_alert(command="pwd"))
    retrieved = store.get_by_id(alert_id)

    assert retrieved is not None
    assert retrieved.command == "pwd"
    assert store.count() == 1


def test_creating_the_app_does_not_create_database_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    create_app()

    # No AlertStore has been constructed anywhere in this test — if
    # creating the app touched the database eagerly, a .db file would
    # appear here.
    assert list(tmp_path.rglob("*.db")) == []


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


def _imported_full_module_names(source: str):
    tree = ast.parse(source)
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


@pytest.mark.parametrize(
    "module_name",
    [
        "api.app",
        "api.dependencies",
        "api.schemas",
        "api.routes.health",
        "api.routes.alerts",
    ],
)
def test_importing_api_does_not_train_model(module_name):
    module = importlib.import_module(module_name)
    source = inspect.getsource(module)

    top_level_names = _imported_top_level_names(source)
    assert "sklearn" not in top_level_names

    full_module_names = _imported_full_module_names(source)
    assert not any(name.startswith("core.ai_engine") for name in full_module_names)
    assert not any(name.startswith("core.honeypot_engine") for name in full_module_names)
    assert not any(name.startswith("core.log_processor") for name in full_module_names)