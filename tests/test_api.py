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
from core.alert_engine.alert_store import AlertStatistics, AlertStore
from api.app import create_app
from api.dependencies import get_alert_store
from api.schemas import AlertSummaryResponse
from core.dataset_manager.builder import DatasetRecord


def _make_alert(
    command: str = "pwd",
    prediction: int = 1,
    score: float = 0.1,
    event_type: str = "cowrie.command.input",
    source_ip: str = "127.0.0.1",
) -> Alert:
    record = DatasetRecord(
        timestamp="2026-08-19T18:00:22.557428Z",
        source_ip=source_ip,
        session_id="ce82815367a4",
        protocol="ssh",
        honeypot="Cowrie",
        event_type=event_type,
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


ALERT_FIELDS = {
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

SUMMARY_FIELDS = {
    "total_alerts",
    "anomaly_count",
    "normal_count",
    "anomaly_rate",
    "event_type_counts",
    "source_ip_counts",
    "score_min",
    "score_max",
    "score_average",
}


def _seed_mixed_alerts(store):
    """Save 5 alerts with known, hand-computable aggregates.

    scores: 0.2, 0.4, -0.6, -0.2, 0.0  -> min -0.6, max 0.4, avg -0.04
    anomalies (prediction -1): the -0.6 and -0.2 rows -> 2 of 5
    event_type: 4 x cowrie.command.input, 1 x cowrie.login.failed
    source_ip: 10.0.0.1 x2, 10.0.0.2 x2, 10.0.0.3 x1
    """
    rows = [
        ("a", 1, 0.2, "cowrie.command.input", "10.0.0.1"),
        ("b", 1, 0.4, "cowrie.command.input", "10.0.0.1"),
        ("c", -1, -0.6, "cowrie.command.input", "10.0.0.2"),
        ("d", -1, -0.2, "cowrie.login.failed", "10.0.0.2"),
        ("e", 1, 0.0, "cowrie.command.input", "10.0.0.3"),
    ]
    ids = []
    for command, prediction, score, event_type, source_ip in rows:
        ids.append(
            store.save(
                _make_alert(
                    command=command,
                    prediction=prediction,
                    score=score,
                    event_type=event_type,
                    source_ip=source_ip,
                )
            )
        )
    return ids


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
    # Phase 2 only ADDED get_statistics() to AlertStore — save(),
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


# --------------------------------------------------------------------
# GET /api/v1/alerts/{alert_id}
# --------------------------------------------------------------------


def test_alert_detail_returns_200_for_existing_alert(api):
    client, store = api
    alert_id = store.save(_make_alert(command="whoami"))

    response = client.get(f"/api/v1/alerts/{alert_id}")

    assert response.status_code == 200


def test_alert_detail_returns_the_requested_alert(api):
    client, store = api
    first_id = store.save(_make_alert(command="first", prediction=1, score=0.25))
    second_id = store.save(_make_alert(command="second", prediction=-1, score=-0.5))

    first = client.get(f"/api/v1/alerts/{first_id}").json()
    second = client.get(f"/api/v1/alerts/{second_id}").json()

    assert first["command"] == "first"
    assert first["prediction"] == 1
    assert first["is_anomaly"] is False
    assert first["score"] == 0.25
    assert second["command"] == "second"
    assert second["prediction"] == -1
    assert second["is_anomaly"] is True
    assert second["score"] == -0.5


def test_alert_detail_has_exactly_the_alert_response_fields(api):
    client, store = api
    alert_id = store.save(_make_alert())

    payload = client.get(f"/api/v1/alerts/{alert_id}").json()

    # Same flat shape as the list endpoint — and no id / DB internals.
    assert set(payload.keys()) == ALERT_FIELDS


def test_alert_detail_uses_same_representation_as_list_endpoint(api):
    client, store = api
    alert_id = store.save(_make_alert(command="uname -a", prediction=-1, score=-0.3))

    detail = client.get(f"/api/v1/alerts/{alert_id}").json()
    listed = client.get("/api/v1/alerts").json()[0]

    assert detail == listed


def test_alert_detail_unknown_id_returns_404(api):
    client, _ = api

    response = client.get("/api/v1/alerts/9999")

    assert response.status_code == 404


def test_alert_detail_404_uses_generic_message_without_db_internals(api):
    client, store = api
    store.save(_make_alert())

    response = client.get("/api/v1/alerts/9999")

    assert response.json() == {"detail": "Alert not found."}
    body = response.text.lower()
    for leaked in ("sqlite", "select", "traceback", "alerts.db", "table"):
        assert leaked not in body


def test_alert_detail_non_integer_id_returns_422(api):
    client, _ = api

    response = client.get("/api/v1/alerts/not-a-number")

    assert response.status_code == 422


# --------------------------------------------------------------------
# GET /api/v1/alerts/summary
# --------------------------------------------------------------------


def test_summary_returns_200(api):
    client, _ = api

    response = client.get("/api/v1/alerts/summary")

    assert response.status_code == 200


def test_summary_route_is_not_shadowed_by_alert_detail_route(api):
    # Regression guard: if "/alerts/{alert_id}" were registered before
    # "/alerts/summary", FastAPI would try to parse "summary" as an int
    # and answer 422 instead of the summary payload.
    client, store = api
    _seed_mixed_alerts(store)

    response = client.get("/api/v1/alerts/summary")

    assert response.status_code != 422
    assert response.status_code == 200
    assert "total_alerts" in response.json()


def test_summary_has_exactly_the_expected_fields(api):
    client, store = api
    _seed_mixed_alerts(store)

    payload = client.get("/api/v1/alerts/summary").json()

    assert set(payload.keys()) == SUMMARY_FIELDS


def test_summary_total_alerts_is_correct(api):
    client, store = api
    _seed_mixed_alerts(store)

    assert client.get("/api/v1/alerts/summary").json()["total_alerts"] == 5


def test_summary_anomaly_count_is_correct(api):
    client, store = api
    _seed_mixed_alerts(store)

    assert client.get("/api/v1/alerts/summary").json()["anomaly_count"] == 2


def test_summary_normal_count_is_correct(api):
    client, store = api
    _seed_mixed_alerts(store)

    assert client.get("/api/v1/alerts/summary").json()["normal_count"] == 3


def test_summary_anomaly_rate_is_a_ratio_not_a_percentage(api):
    client, store = api
    _seed_mixed_alerts(store)

    rate = client.get("/api/v1/alerts/summary").json()["anomaly_rate"]

    assert rate == pytest.approx(0.4)
    assert 0.0 <= rate <= 1.0


def test_summary_event_type_counts_are_correct(api):
    client, store = api
    _seed_mixed_alerts(store)

    payload = client.get("/api/v1/alerts/summary").json()

    assert payload["event_type_counts"] == {
        "cowrie.command.input": 4,
        "cowrie.login.failed": 1,
    }


def test_summary_source_ip_counts_are_correct(api):
    client, store = api
    _seed_mixed_alerts(store)

    payload = client.get("/api/v1/alerts/summary").json()

    assert payload["source_ip_counts"] == {
        "10.0.0.1": 2,
        "10.0.0.2": 2,
        "10.0.0.3": 1,
    }


def test_summary_score_statistics_are_correct(api):
    client, store = api
    _seed_mixed_alerts(store)

    payload = client.get("/api/v1/alerts/summary").json()

    assert payload["score_min"] == pytest.approx(-0.6)
    assert payload["score_max"] == pytest.approx(0.4)
    assert payload["score_average"] == pytest.approx(-0.04)


def test_summary_is_internally_consistent(api):
    client, store = api
    _seed_mixed_alerts(store)

    payload = client.get("/api/v1/alerts/summary").json()

    assert payload["anomaly_count"] + payload["normal_count"] == payload["total_alerts"]
    assert sum(payload["event_type_counts"].values()) == payload["total_alerts"]
    assert sum(payload["source_ip_counts"].values()) == payload["total_alerts"]


def test_summary_covers_all_alerts_not_just_the_default_list_page(api):
    # The summary must aggregate the WHOLE table. If it were derived
    # from list_recent(limit=100) it would stop at 100 here.
    client, store = api
    for i in range(120):
        is_outlier = i % 4 == 0  # 30 outliers out of 120
        store.save(
            _make_alert(
                command=f"cmd-{i}",
                prediction=-1 if is_outlier else 1,
                score=-0.5 if is_outlier else 0.5,
            )
        )

    listed = client.get("/api/v1/alerts").json()
    summary = client.get("/api/v1/alerts/summary").json()

    assert len(listed) == 100
    assert summary["total_alerts"] == 120
    assert summary["anomaly_count"] == 30
    assert summary["normal_count"] == 90
    assert summary["anomaly_rate"] == pytest.approx(0.25)


def test_summary_of_empty_store_returns_zero_valued_payload(api):
    client, _ = api

    response = client.get("/api/v1/alerts/summary")

    assert response.status_code == 200
    assert response.json() == {
        "total_alerts": 0,
        "anomaly_count": 0,
        "normal_count": 0,
        "anomaly_rate": 0.0,
        "event_type_counts": {},
        "source_ip_counts": {},
        "score_min": None,
        "score_max": None,
        "score_average": None,
    }


def test_summary_describes_persisted_records_only_not_all_model_predictions(api):
    # The live pipeline's AlertDispatcher forwards only anomalous
    # results, so a store populated by it can hold anomaly records only.
    # The summary must describe exactly what is persisted: here every
    # persisted record is an anomaly, so normal_count is 0 and
    # anomaly_rate is 1.0 — even though the model that produced these
    # alerts will have made many normal/inlier predictions that were
    # never stored and are therefore (correctly) not counted.
    client, store = api
    for i in range(3):
        store.save(_make_alert(command=f"outlier-{i}", prediction=-1, score=-0.5))

    payload = client.get("/api/v1/alerts/summary").json()

    assert payload["total_alerts"] == 3
    assert payload["anomaly_count"] == 3
    assert payload["normal_count"] == 0
    assert payload["anomaly_rate"] == pytest.approx(1.0)


def test_summary_documentation_states_persisted_records_scope(api):
    # Protects the semantic clarification itself: the summary's
    # documentation — including the schema description API consumers
    # see in /openapi.json — must say it covers persisted records only
    # and that normal_count is not the model's total normal/inlier
    # predictions.
    client, _ = api
    openapi_description = client.get("/openapi.json").json()["components"]["schemas"][
        "AlertSummaryResponse"
    ]["description"]

    documented = {
        "AlertStatistics": AlertStatistics.__doc__,
        "AlertSummaryResponse": AlertSummaryResponse.__doc__,
        "openapi AlertSummaryResponse description": openapi_description,
    }

    for name, text in documented.items():
        # Whitespace- and case-insensitive: docstrings wrap lines and
        # use capitalised emphasis (e.g. "NOT").
        normalized = " ".join(text.split()).lower()
        assert "persisted records only" in normalized, name
        assert "normal_count" in normalized, name
        assert "not the total number of normal/inlier predictions" in normalized, name


def test_alerts_list_and_health_still_work_after_phase_2(api):
    client, store = api
    _seed_mixed_alerts(store)

    assert client.get("/health").status_code == 200
    assert client.get("/health").json() == {"status": "ok"}
    listed = client.get("/api/v1/alerts")
    assert listed.status_code == 200
    assert len(listed.json()) == 5


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