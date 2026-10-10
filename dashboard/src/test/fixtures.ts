import type { AlertSummaryResponse } from '../api/types';

/** A mixed store: 5 persisted records, 2 flagged as outliers, 3 not. */
export function makeSummary(overrides: Partial<AlertSummaryResponse> = {}): AlertSummaryResponse {
  return {
    total_alerts: 5,
    anomaly_count: 2,
    normal_count: 3,
    anomaly_rate: 0.4,
    event_type_counts: { 'cowrie.command.input': 4, 'cowrie.login.failed': 1 },
    source_ip_counts: { '10.0.0.1': 2, '10.0.0.2': 2, '10.0.0.3': 1 },
    score_min: -0.6,
    score_max: 0.4,
    score_average: -0.04,
    ...overrides,
  };
}

/** What a store populated only by flagged results looks like. */
export function makeAllFlaggedSummary(total = 3): AlertSummaryResponse {
  return makeSummary({
    total_alerts: total,
    anomaly_count: total,
    normal_count: 0,
    anomaly_rate: 1,
    score_max: -0.1,
  });
}

export function makeEmptySummary(): AlertSummaryResponse {
  return {
    total_alerts: 0,
    anomaly_count: 0,
    normal_count: 0,
    anomaly_rate: 0,
    event_type_counts: {},
    source_ip_counts: {},
    score_min: null,
    score_max: null,
    score_average: null,
  };
}
