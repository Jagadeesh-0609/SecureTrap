"""Alert Engine — Persistent Alert Storage for SecureTrap.

Persists Alert objects to a local SQLite database so anomaly alerts
survive process termination and can be queried later. This is
storage/querying only — no anomaly detection, filtering, feature
extraction, or notification happens here.

This module depends on Alert, AnomalyResult, and DatasetRecord only
(the latter two purely to reconstruct a well-formed Alert on read). It
has no dependency on the AI Engine, the runtime layer, or any
honeypot/log-processing component.
"""

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Union

from core.ai_engine.anomaly_result import AnomalyResult
from core.alert_engine.alert import Alert
from core.dataset_manager.builder import DatasetRecord

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    session_id TEXT NOT NULL,
    protocol TEXT NOT NULL,
    honeypot TEXT NOT NULL,
    event_type TEXT NOT NULL,
    command TEXT NOT NULL,
    prediction INTEGER NOT NULL,
    score REAL NOT NULL,
    is_anomaly INTEGER NOT NULL
)
"""

_INSERT_SQL = """
INSERT INTO alerts (
    timestamp, source_ip, session_id, protocol, honeypot,
    event_type, command, prediction, score, is_anomaly
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_SELECT_COLUMNS = (
    "id, timestamp, source_ip, session_id, protocol, honeypot, "
    "event_type, command, prediction, score, is_anomaly"
)

_SELECT_BY_ID_SQL = f"SELECT {_SELECT_COLUMNS} FROM alerts WHERE id = ?"

_SELECT_RECENT_SQL = f"SELECT {_SELECT_COLUMNS} FROM alerts ORDER BY id DESC LIMIT ?"

# Aggregate statistics are computed by SQLite over the WHOLE table —
# never from a limited list_recent() page. COALESCE keeps SUM() at 0
# (instead of NULL) for an empty table; MIN/MAX/AVG stay NULL (None)
# when there are no rows, which is the honest "no data" answer.
_STATISTICS_SCALARS_SQL = (
    "SELECT COUNT(*), "
    "COALESCE(SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END), 0), "
    "MIN(score), MAX(score), AVG(score) FROM alerts"
)

_EVENT_TYPE_COUNTS_SQL = (
    "SELECT event_type, COUNT(*) FROM alerts GROUP BY event_type ORDER BY event_type"
)

_SOURCE_IP_COUNTS_SQL = (
    "SELECT source_ip, COUNT(*) FROM alerts GROUP BY source_ip ORDER BY source_ip"
)

# Placeholder values for the DatasetRecord fields AlertStore never
# persists and never recomputes (category, severity, and every
# enrichment feature). AlertStore performs no feature extraction or
# classification of any kind — these exist only because DatasetRecord
# requires them to be constructible, not because they reflect real
# analysis of the retrieved alert.
_UNKNOWN_CATEGORY = "unknown"
_UNKNOWN_SEVERITY = "unknown"


@dataclass
class AlertStatistics:
    """Aggregate statistics over every alert persisted in an AlertStore.

    SCOPE — persisted records only. Every value here describes the
    rows currently stored in the AlertStore and nothing else. It is
    NOT a summary of everything the model has predicted: the live
    pipeline's AlertDispatcher forwards only anomalous results
    (is_anomaly == True) for persistence, so normal/inlier predictions
    produced during live inference are never stored and are therefore
    never counted here. A store populated by the live pipeline will
    normally contain anomaly records only. (Non-anomalous records can
    exist only if something other than the live pipeline — a test, for
    instance — saves them directly.)

    Pure storage-level aggregates — counts, a ratio, and basic score
    statistics. Nothing here interprets the data as a security
    judgment.

    Attributes:
        total_alerts: Number of persisted alert records (rows).
        anomaly_count: Persisted records where is_anomaly is true —
            i.e. alerts IsolationForest flagged as statistical
            outliers (prediction == -1). This is NOT a count of
            confirmed attacks.
        normal_count: Persisted records marked non-anomalous
            (is_anomaly false), computed as total_alerts -
            anomaly_count. This is NOT the total number of
            normal/inlier predictions produced by the model — the live
            pipeline does not persist those, so for a store populated
            by the live pipeline this will normally be 0.
        anomaly_rate: anomaly_count / total_alerts as a ratio in the
            range 0.0–1.0 (not a percentage). It is the share of
            PERSISTED records that are anomalous — not the share of all
            model predictions flagged as anomalies. 0.0 when there are
            no records.
        event_type_counts: Number of persisted records per event_type.
        source_ip_counts: Number of persisted records per source_ip.
        score_min: Lowest score among persisted records, or None if
            there are none.
        score_max: Highest score among persisted records, or None if
            there are none.
        score_average: Mean score among persisted records, or None if
            there are none. Scores are IsolationForest
            decision-function values — lower means more anomalous —
            not probabilities.
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


class AlertStore:
    """Persists and retrieves Alert objects using SQLite.

    Uses a short-lived sqlite3 connection per operation rather than
    holding one open across calls, and commits writes explicitly.
    Every query is parameterized — alert values are never interpolated
    into SQL text.

    Retrieved Alert objects are reconstructed from only the fields
    that were actually persisted (Alert's own 10 fields). The
    DatasetRecord fields AlertStore never stores (category, severity,
    and the enrichment booleans) are filled with clearly-labeled
    placeholders — never recomputed, since recomputing them would mean
    AlertStore performing feature extraction, which is out of scope.
    The identity of the original AnomalyResult/DatasetRecord objects
    from the process that created the alert is not preserved across a
    save/load round-trip — only their persisted field values are.
    """

    def __init__(self, path: Union[str, Path]) -> None:
        """Create (or open) the SQLite-backed alert store at `path`.

        Creates any missing parent directories, the database file, and
        the `alerts` table if they do not already exist.

        Args:
            path: Filesystem path to the SQLite database file.
        """
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

        connection = sqlite3.connect(self._path)
        try:
            connection.execute(_CREATE_TABLE_SQL)
            connection.commit()
        finally:
            connection.close()

    def save(self, alert: Alert) -> int:
        """Persist an Alert and return its new row ID.

        Args:
            alert: The Alert to persist. Not modified.

        Returns:
            The integer ID SQLite assigned to the new row. This ID is
            storage metadata only — it is not an AI or security label.
        """
        connection = sqlite3.connect(self._path)
        try:
            cursor = connection.execute(
                _INSERT_SQL,
                (
                    alert.timestamp,
                    alert.source_ip,
                    alert.session_id,
                    alert.protocol,
                    alert.honeypot,
                    alert.event_type,
                    alert.command,
                    alert.prediction,
                    alert.score,
                    int(alert.is_anomaly),
                ),
            )
            connection.commit()
            return cursor.lastrowid
        finally:
            connection.close()

    def get_by_id(self, alert_id: int) -> Optional[Alert]:
        """Retrieve a stored Alert by its row ID.

        Args:
            alert_id: The ID returned by a previous save() call.

        Returns:
            The reconstructed Alert, or None if no row with that ID
            exists.
        """
        connection = sqlite3.connect(self._path)
        try:
            row = connection.execute(_SELECT_BY_ID_SQL, (alert_id,)).fetchone()
        finally:
            connection.close()

        if row is None:
            return None

        return self._row_to_alert(row)

    def list_recent(self, limit: int = 100) -> List[Alert]:
        """List the most recently saved alerts, newest first.

        Args:
            limit: Maximum number of alerts to return. Must be a
                positive integer. Defaults to 100.

        Returns:
            Up to `limit` Alerts, ordered by insertion id descending
            (newest first).

        Raises:
            ValueError: If `limit` is not a positive integer.
        """
        if limit <= 0:
            raise ValueError(f"limit must be a positive integer, got {limit!r}.")

        connection = sqlite3.connect(self._path)
        try:
            rows = connection.execute(_SELECT_RECENT_SQL, (limit,)).fetchall()
        finally:
            connection.close()

        return [self._row_to_alert(row) for row in rows]

    def count(self) -> int:
        """Return the total number of stored alert rows."""
        connection = sqlite3.connect(self._path)
        try:
            (total,) = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()
        finally:
            connection.close()
        return total

    def get_statistics(self) -> AlertStatistics:
        """Compute aggregate statistics over ALL stored alerts.

        Aggregation happens inside SQLite (COUNT / SUM / MIN / MAX /
        AVG / GROUP BY) over the entire table — it is never derived
        from a limited list_recent() page. All three queries run inside
        one explicit read transaction, so a writer committing between
        them cannot make the totals, the anomaly count, and the
        per-event-type / per-IP breakdowns disagree with each other.

        Returns:
            An AlertStatistics. For an empty store: zero counts,
            anomaly_rate 0.0, empty count dicts, and None score
            statistics.
        """
        connection = sqlite3.connect(self._path)
        try:
            connection.execute("BEGIN")
            (
                total_alerts,
                anomaly_count,
                score_min,
                score_max,
                score_average,
            ) = connection.execute(_STATISTICS_SCALARS_SQL).fetchone()
            event_type_counts = dict(connection.execute(_EVENT_TYPE_COUNTS_SQL).fetchall())
            source_ip_counts = dict(connection.execute(_SOURCE_IP_COUNTS_SQL).fetchall())
        finally:
            connection.close()

        return AlertStatistics(
            total_alerts=total_alerts,
            anomaly_count=anomaly_count,
            normal_count=total_alerts - anomaly_count,
            anomaly_rate=(anomaly_count / total_alerts) if total_alerts > 0 else 0.0,
            event_type_counts=event_type_counts,
            source_ip_counts=source_ip_counts,
            score_min=score_min,
            score_max=score_max,
            score_average=score_average,
        )

    @staticmethod
    def _row_to_alert(row) -> Alert:
        """Reconstruct an Alert from a stored row.

        Only the fields Alert actually persists are used. DatasetRecord
        requires several additional fields (category, severity, and the
        enrichment booleans) that AlertStore never persists or
        recomputes; those are filled with clearly-labeled placeholders
        purely so DatasetRecord can be constructed, not because they
        reflect real analysis of this alert.
        """
        (
            _row_id,
            timestamp,
            source_ip,
            session_id,
            protocol,
            honeypot,
            event_type,
            command,
            prediction,
            score,
            is_anomaly,
        ) = row

        record = DatasetRecord(
            timestamp=timestamp,
            source_ip=source_ip,
            session_id=session_id,
            protocol=protocol,
            honeypot=honeypot,
            event_type=event_type,
            category=_UNKNOWN_CATEGORY,
            severity=_UNKNOWN_SEVERITY,
            command=command,
            has_command=False,
            command_length=0,
            has_url=False,
            has_ip_address=False,
            has_file_path=False,
            has_shell_metacharacters=False,
        )
        result = AnomalyResult(
            record=record,
            prediction=int(prediction),
            score=float(score),
            is_anomaly=bool(is_anomaly),
        )
        return Alert(
            result=result,
            timestamp=timestamp,
            source_ip=source_ip,
            session_id=session_id,
            protocol=protocol,
            honeypot=honeypot,
            event_type=event_type,
            command=command,
            prediction=int(prediction),
            score=float(score),
            is_anomaly=bool(is_anomaly),
        )