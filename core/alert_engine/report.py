"""Alert Engine — Alert Reporting for SecureTrap.

Provides read-only, operator-facing summaries and recent-alert
queries over an existing AlertStore. This is presentation-oriented
aggregation only — it performs no AI/model calls, no detection, no
dispatch, and no database writes; it never modifies a stored Alert or
the database itself.

This module depends on AlertStore and Alert only. It has no
dependency on the AI Engine, the runtime layer, or any honeypot/
log-processing/dataset component.
"""

from dataclasses import dataclass
from typing import List, Optional

from core.alert_engine.alert import Alert
from core.alert_engine.alert_store import AlertStore


@dataclass
class AlertSummary:
    """An aggregate, read-only view of everything currently in an AlertStore.

    Attributes:
        total_alerts: Total number of alerts currently stored.
        anomaly_alerts: Number of stored alerts with is_anomaly=True.
            "Anomaly" here means only what IsolationForest flagged as
            an outlier — never renamed to "attack."
        normal_alerts: Number of stored alerts with is_anomaly=False.
        latest_timestamp: The `timestamp` field of the most recently
            stored alert, determined by AlertStore's own newest-first
            ordering (not a lexicographic sort of timestamp strings),
            or None if the store is empty.
    """

    total_alerts: int
    anomaly_alerts: int
    normal_alerts: int
    latest_timestamp: Optional[str]


class AlertReporter:
    """Read-only reporting over an existing AlertStore.

    Never writes to the database and never modifies the Alert objects
    it returns. Reuses AlertStore's existing public methods
    (`count()` and `list_recent()`) rather than writing any SQL of its
    own.
    """

    def __init__(self, alert_store: AlertStore) -> None:
        """Create an AlertReporter over an existing AlertStore.

        Args:
            alert_store: An AlertStore-compatible object providing
                `count() -> int` and
                `list_recent(limit) -> list[Alert]`.
        """
        self._alert_store = alert_store

    def summary(self) -> AlertSummary:
        """Build an aggregate summary of everything currently stored.

        Returns:
            An AlertSummary with total/anomaly/normal counts and the
            most recently stored alert's timestamp (or None if the
            store is empty).
        """
        total_alerts = self._alert_store.count()

        if total_alerts == 0:
            return AlertSummary(
                total_alerts=0,
                anomaly_alerts=0,
                normal_alerts=0,
                latest_timestamp=None,
            )

        all_alerts = self._alert_store.list_recent(limit=total_alerts)
        anomaly_alerts = sum(1 for alert in all_alerts if alert.is_anomaly)
        normal_alerts = total_alerts - anomaly_alerts

        # list_recent() is newest-first, so the first item is the
        # latest stored alert by AlertStore's own insertion order.
        latest_timestamp = all_alerts[0].timestamp

        return AlertSummary(
            total_alerts=total_alerts,
            anomaly_alerts=anomaly_alerts,
            normal_alerts=normal_alerts,
            latest_timestamp=latest_timestamp,
        )

    def recent(self, limit: int = 10) -> List[Alert]:
        """Return the most recently stored alerts, newest first.

        Delegates entirely to AlertStore.list_recent() — no SQL or
        ordering logic of its own.

        Args:
            limit: Maximum number of alerts to return. Must be a
                positive integer; invalid values are rejected exactly
                as AlertStore.list_recent() already rejects them.

        Returns:
            Up to `limit` Alerts, in AlertStore's own newest-first
            order.
        """
        return self._alert_store.list_recent(limit)