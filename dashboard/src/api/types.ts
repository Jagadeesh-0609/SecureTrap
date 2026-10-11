/**
 * TypeScript mirrors of the SecureTrap API response schemas
 * (api/schemas.py in the backend). Field names match the backend exactly.
 */

/** GET /health */
export interface HealthResponse {
  /** "ok" means only that the API process answered. */
  status: string;
}

/**
 * GET /api/v1/alerts/summary
 *
 * Aggregate statistics over the alert records PERSISTED in the alert store,
 * not over every prediction the model has made.
 */
export interface AlertSummaryResponse {
  total_alerts: number;
  /** Persisted records flagged as statistical outliers (not confirmed attacks). */
  anomaly_count: number;
  /** Persisted records NOT flagged as outliers; not all normal predictions. */
  normal_count: number;
  /** anomaly_count / total_alerts as a ratio in 0.0-1.0 (not a percentage). */
  anomaly_rate: number;
  event_type_counts: Record<string, number>;
  source_ip_counts: Record<string, number>;
  score_min: number | null;
  score_max: number | null;
  score_average: number | null;
}

/**
 * One persisted alert, as returned by GET /api/v1/alerts (a JSON array of
 * these) and GET /api/v1/alerts/{alert_id}.
 *
 * `id` is the alert's persisted database ID (storage metadata: it reflects the
 * order alerts were persisted, not their event time). The remaining fields
 * mirror the backend's Alert domain model exactly. The API has no severity,
 * category or confidence field, and none is invented here.
 */
export interface AlertResponse {
  id: number;
  /** ISO 8601 event time as recorded by the honeypot (normally UTC, "...Z"). */
  timestamp: string;
  source_ip: string;
  session_id: string;
  protocol: string;
  honeypot: string;
  event_type: string;
  /** Attacker-controlled free text: untrusted, rendered only as text. */
  command: string;
  /** IsolationForest's raw output: 1 = inlier, -1 = outlier. */
  prediction: number;
  /** IsolationForest decision_function score. Not a probability. */
  score: number;
  /** True exactly when prediction is -1: a statistical outlier, not a verdict. */
  is_anomaly: boolean;
}
