import { ApiError } from './client';
import type { AlertSummaryResponse, HealthResponse } from './types';

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
