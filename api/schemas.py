"""Pydantic response schemas for the SecureTrap API.

These mirror existing domain objects (Alert) field-for-field — no
renaming, no reinterpretation, no new fields invented here. This
module owns presentation shape only; AlertStore and Alert remain the
single source of truth for what an alert actually contains.
"""

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Response body for GET /health."""

    status: str


class AlertResponse(BaseModel):
    """Response body for one alert in GET /api/v1/alerts.

    A field-for-field mirror of core.alert_engine.alert.Alert's flat
    fields, excluding `result` — which carries the full internal
    AnomalyResult/DatasetRecord chain and isn't meant to cross the API
    boundary as-is. Field names and semantics are identical to Alert's
    own: `prediction` and `is_anomaly` still mean exactly what
    IsolationForest produced (1 = inlier/normal, -1 = outlier/anomaly;
    is_anomaly is not a confirmed-attack judgment), never relabeled
    here.
    """

    timestamp: str
    source_ip: str
    session_id: str
    protocol: str
    honeypot: str
    event_type: str
    command: str
    prediction: int
    score: float
    is_anomaly: bool