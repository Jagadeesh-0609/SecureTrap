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
