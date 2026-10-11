import { ApiError } from './client';
import type { AlertResponse, AlertSummaryResponse, HealthResponse } from './types';

/*
 * Runtime checks for API responses. TypeScript types are erased at runtime, so
 * a response that does not match the contract (an older or newer API, a proxy
 * error page served as JSON, ...) would otherwise flow into the UI as
 * undefined / NaN. Failing here turns that into a clear "unexpected response"
 * state instead.
 */

function invalid(field: string): never {
  throw new ApiError(
    'invalid',
    `Unexpected API response: "${field}" is missing or has the wrong type.`,
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function nonNegativeInteger(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    return invalid(field);
  }
  return value;
}

function positiveInteger(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    return invalid(field);
  }
  return value;
}

function safeInteger(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    return invalid(field);
  }
  return value;
}

function finiteNumber(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return invalid(field);
  }
  return value;
}

function text(value: unknown, field: string): string {
  if (typeof value !== 'string') {
    return invalid(field);
  }
  return value;
}

function flag(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') {
    return invalid(field);
  }
  return value;
}

function ratio(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1) {
    return invalid(field);
  }
  return value;
}

function nullableFiniteNumber(value: unknown, field: string): number | null {
  if (value === null) {
    return null;
  }
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return invalid(field);
  }
  return value;
}

function countMap(value: unknown, field: string): Record<string, number> {
  if (!isRecord(value)) {
    return invalid(field);
  }
  const entries = Object.entries(value).map(([key, count]): [string, number] => [
    key,
    nonNegativeInteger(count, field),
  ]);
  // fromEntries defines own properties, so an untrusted key such as
  // "__proto__" stays plain data and never touches the prototype chain.
  return Object.fromEntries(entries);
}

export function parseHealthResponse(value: unknown): HealthResponse {
  if (!isRecord(value)) {
    return invalid('response');
  }
  if (typeof value.status !== 'string') {
    return invalid('status');
  }
  return { status: value.status };
}

export function parseAlertSummaryResponse(value: unknown): AlertSummaryResponse {
  if (!isRecord(value)) {
    return invalid('response');
  }
  return {
    total_alerts: nonNegativeInteger(value.total_alerts, 'total_alerts'),
    anomaly_count: nonNegativeInteger(value.anomaly_count, 'anomaly_count'),
    normal_count: nonNegativeInteger(value.normal_count, 'normal_count'),
    anomaly_rate: ratio(value.anomaly_rate, 'anomaly_rate'),
    event_type_counts: countMap(value.event_type_counts, 'event_type_counts'),
    source_ip_counts: countMap(value.source_ip_counts, 'source_ip_counts'),
    score_min: nullableFiniteNumber(value.score_min, 'score_min'),
    score_max: nullableFiniteNumber(value.score_max, 'score_max'),
    score_average: nullableFiniteNumber(value.score_average, 'score_average'),
  };
}

/**
 * One alert. `prefix` names the position in a list ("alerts[3].") so a bad
 * field can be located; it is built from an array index, never from API data.
 * Fields the dashboard does not know about are ignored, not copied.
 */
function parseAlertAt(value: unknown, prefix: string): AlertResponse {
  if (!isRecord(value)) {
    return invalid(prefix === '' ? 'response' : prefix.replace(/\.$/, ''));
  }
  return {
    id: positiveInteger(value.id, `${prefix}id`),
    timestamp: text(value.timestamp, `${prefix}timestamp`),
    source_ip: text(value.source_ip, `${prefix}source_ip`),
    session_id: text(value.session_id, `${prefix}session_id`),
    protocol: text(value.protocol, `${prefix}protocol`),
    honeypot: text(value.honeypot, `${prefix}honeypot`),
    event_type: text(value.event_type, `${prefix}event_type`),
    command: text(value.command, `${prefix}command`),
    prediction: safeInteger(value.prediction, `${prefix}prediction`),
    score: finiteNumber(value.score, `${prefix}score`),
    is_anomaly: flag(value.is_anomaly, `${prefix}is_anomaly`),
  };
}

/** GET /api/v1/alerts/{alert_id} */
export function parseAlertResponse(value: unknown): AlertResponse {
  return parseAlertAt(value, '');
}

/**
 * GET /api/v1/alerts: a JSON array of alerts. One malformed element makes the
 * whole response invalid, and so does a repeated ID (IDs are unique, and the
 * UI uses them as keys and in links).
 */
export function parseAlertListResponse(value: unknown): AlertResponse[] {
  if (!Array.isArray(value)) {
    return invalid('response');
  }
  const seen = new Set<number>();
  return value.map((item: unknown, index) => {
    const alert = parseAlertAt(item, `alerts[${index}].`);
    if (seen.has(alert.id)) {
      return invalid(`alerts[${index}].id`);
    }
    seen.add(alert.id);
    return alert;
  });
}
