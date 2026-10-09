"""Read-only alert routes for the SecureTrap API."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query

from core.alert_engine.alert import Alert
from core.alert_engine.alert_store import AlertStore
from api.dependencies import get_alert_store
from api.schemas import AlertResponse, AlertSummaryResponse

router = APIRouter(prefix="/api/v1", tags=["alerts"])


def _to_response(alert: Alert) -> AlertResponse:
    """Map an Alert to the flat AlertResponse shared by list and detail."""
    return AlertResponse(
        timestamp=alert.timestamp,
        source_ip=alert.source_ip,
        session_id=alert.session_id,
        protocol=alert.protocol,
        honeypot=alert.honeypot,
        event_type=alert.event_type,
        command=alert.command,
        prediction=alert.prediction,
        score=alert.score,
        is_anomaly=alert.is_anomaly,
    )


@router.get("/alerts", response_model=List[AlertResponse])
def list_alerts(
    limit: int = Query(100, gt=0, description="Maximum number of alerts to return, newest first."),
    alert_store: AlertStore = Depends(get_alert_store),
) -> List[AlertResponse]:
    """List the most recently persisted alerts, newest first.

    Delegates entirely to AlertStore.list_recent() — this route
    contains no SQL and duplicates none of AlertStore's internals.
    Returns an empty list, not an error, when no alerts are stored.
    `limit` must be positive; FastAPI/Pydantic reject anything else
    with a 422 before this function ever runs.
    """
    return [_to_response(alert) for alert in alert_store.list_recent(limit=limit)]


# NOTE: this route MUST be registered before "/alerts/{alert_id}".
# FastAPI matches routes in registration order, so if the parameterized
# route came first, "/alerts/summary" would be captured with
# alert_id="summary" and rejected with a 422 (it is not an int).
@router.get("/alerts/summary", response_model=AlertSummaryResponse)
def alert_summary(
    alert_store: AlertStore = Depends(get_alert_store),
) -> AlertSummaryResponse:
    """Aggregate statistics over every persisted alert.

    Delegates entirely to AlertStore.get_statistics(), which aggregates
    inside SQLite over the whole table — this route contains no SQL and
    never derives the numbers from a limited list_recent() page.
    `anomaly_rate` is a ratio (0.0–1.0), not a percentage. An empty
    store yields zero counts, a rate of 0.0, empty dictionaries, and
    null score statistics. "Anomaly" means an IsolationForest
    statistical outlier, not a confirmed attack.
    """
    statistics = alert_store.get_statistics()
    return AlertSummaryResponse(
        total_alerts=statistics.total_alerts,
        anomaly_count=statistics.anomaly_count,
        normal_count=statistics.normal_count,
        anomaly_rate=statistics.anomaly_rate,
        event_type_counts=statistics.event_type_counts,
        source_ip_counts=statistics.source_ip_counts,
        score_min=statistics.score_min,
        score_max=statistics.score_max,
        score_average=statistics.score_average,
    )


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: int,
    alert_store: AlertStore = Depends(get_alert_store),
) -> AlertResponse:
    """Return one persisted alert by its id.

    Delegates to AlertStore.get_by_id() and reuses the same flat
    AlertResponse as the list endpoint. An unknown id yields HTTP 404
    with a generic message — no database internals are exposed.
    """
    alert = alert_store.get_by_id(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return _to_response(alert)