"""Pydantic response schemas for the SecureTrap API.

This module defines API presentation schemas only. It performs no
detection and does not reinterpret model predictions.

AlertResponse combines two things that both come from persisted data:
the storage identifier (`id`) supplied by AlertStore, and the
persisted alert fields from the Alert domain model. `id` is storage
metadata — it is not a field on the Alert domain model. The
remaining alert field names and semantics are unchanged from
Alert's own.

AlertSummaryResponse represents aggregate statistics over persisted
records only.
"""

from typing import Dict, Optional

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Response body for GET /health."""

    status: str


class AlertResponse(BaseModel):
    """Response body for one alert in GET /api/v1/alerts and GET /api/v1/alerts/{alert_id}.

    Mirrors core.alert_engine.alert.Alert's flat fields, excluding
    `result` — which carries the full internal AnomalyResult /
    DatasetRecord chain and isn't meant to cross the API boundary
    as-is — plus the stored alert's `id`. Field names and semantics
    are identical to Alert's own: `prediction` and `is_anomaly` still
    mean exactly what IsolationForest produced (1 = inlier/normal,
    -1 = outlier/anomaly; is_anomaly is not a confirmed-attack
    judgment), never relabeled here.

    `id` is the stable persisted alert identifier: the alert's
    database ID, the same value used in GET /api/v1/alerts/{alert_id}
    to retrieve this individual alert. It is storage metadata only —
    not an AI or security label — and it reflects the order alerts
    were persisted, not their event `timestamp`. It is unique within
    one alert database and should not be assumed meaningful across
    different databases.
    """

    id: int
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


class AlertSummaryResponse(BaseModel):
    """Response body for GET /api/v1/alerts/summary.

    Aggregate statistics over EVERY persisted alert (not a recent
    page), mirroring core.alert_engine.alert_store.AlertStatistics
    field-for-field.

    SCOPE — persisted records only. Every value in this response
    describes the alert records currently persisted in the alert
    store, and nothing else. It is not a summary of everything the
    detection model has predicted: the live detection pipeline
    currently persists only alerts for anomalous results, so
    normal/inlier predictions it produces are not stored and are not
    counted here. A store populated by the live pipeline will
    normally contain anomaly records only.

    `normal_count` is the number of persisted records marked
    non-anomalous (is_anomaly false) — not the total number of
    normal/inlier predictions produced by the model. For a store
    populated by the live pipeline it will normally be 0.

    `anomaly_rate` is a ratio in the range 0.0–1.0 (anomaly_count /
    total_alerts), not a percentage. It is the share of PERSISTED
    records that are anomalous, not the share of all model predictions
    flagged as anomalies; it is 0.0 when there are no records.
    `score_min`, `score_max` and `score_average` are null when there
    are no persisted records.

    "Anomaly" here keeps its IsolationForest meaning: a statistical
    outlier (prediction == -1). It is not a confirmed attack, a
    probability, a confidence value, or a threat level.
    """

    total_alerts: int
    anomaly_count: int
    normal_count: int
    anomaly_rate: float
    event_type_counts: Dict[str, int]
    source_ip_counts: Dict[str, int]
    score_min: Optional[float]
    score_max: Optional[float]
    score_average: Optional[float]