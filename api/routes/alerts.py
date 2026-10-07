"""Read-only alert routes for the SecureTrap API."""

from typing import List

from fastapi import APIRouter, Depends, Query

from core.alert_engine.alert_store import AlertStore
from api.dependencies import get_alert_store
from api.schemas import AlertResponse

router = APIRouter(prefix="/api/v1", tags=["alerts"])


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
    alerts = alert_store.list_recent(limit=limit)
    return [
        AlertResponse(
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
        for alert in alerts
    ]