"""Alert Engine — Alert Representation for SecureTrap.

Converts an AnomalyResult into a structured, operator-friendly Alert
that downstream runtime components can consume. This is the internal
alert representation only — no notifications, no persistence, no
queues, and no attack/benign classification.

This module consumes AnomalyResult only. It has no dependency on
sklearn or on any honeypot, log-processing, dataset, or AI-engine
component beyond AnomalyResult itself.
"""

from dataclasses import dataclass

from core.ai_engine.anomaly_result import AnomalyResult


@dataclass
class Alert:
    """An operator-friendly view of one AnomalyResult.

    An Alert represents a model result, not a security verdict. It
    may be built for either a normal or an anomalous result — this
    class does not suppress normal results, and `is_anomaly` here
    means only "IsolationForest marked this an outlier," nothing more.
    Downstream runtime code may choose to emit an external
    notification only when `is_anomaly` is True, but that policy
    decision belongs to that downstream code, not to this class or to
    AlertBuilder.

    Attributes:
        result: The original AnomalyResult this Alert was built from,
            preserved unchanged and by identity — including its
            `record`, so the full chain back to the original
            DatasetRecord remains reachable.
        timestamp: Copied from result.record.timestamp.
        source_ip: Copied from result.record.source_ip.
        session_id: Copied from result.record.session_id.
        protocol: Copied from result.record.protocol.
        honeypot: Copied from result.record.honeypot.
        event_type: Copied from result.record.event_type.
        command: Copied from result.record.command.
        prediction: Copied from result.prediction (1 = inlier/normal,
            -1 = outlier/anomaly — IsolationForest's own semantics,
            never relabeled).
        score: Copied from result.score.
        is_anomaly: Copied from result.is_anomaly.
    """

    result: AnomalyResult
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


class AlertBuilder:
    """Builds an Alert from an AnomalyResult.

    Purely a field-copying operation: no validation (the AnomalyResult
    is assumed already valid, per AnomalyResultBuilder), no additional
    threat interpretation, no I/O, no external dependencies beyond
    AnomalyResult itself. Deterministic — the same AnomalyResult
    always produces the same Alert, and the input is never modified.
    """

    def build(self, result: AnomalyResult) -> Alert:
        """Convert one AnomalyResult into an Alert.

        Args:
            result: A valid AnomalyResult, for either a normal or an
                anomalous prediction. Both are represented the same
                way — this method never suppresses or special-cases
                normal results.

        Returns:
            An Alert with `result` preserved by identity and its
            convenience fields copied from `result.record` and
            `result` itself.
        """
        record = result.record

        return Alert(
            result=result,
            timestamp=record.timestamp,
            source_ip=record.source_ip,
            session_id=record.session_id,
            protocol=record.protocol,
            honeypot=record.honeypot,
            event_type=record.event_type,
            command=record.command,
            prediction=result.prediction,
            score=result.score,
            is_anomaly=result.is_anomaly,
        )