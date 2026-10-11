import { requestJson, type RequestOptions } from './client';
import type { AlertResponse, AlertSummaryResponse, HealthResponse } from './types';
import {
  parseAlertListResponse,
  parseAlertResponse,
  parseAlertSummaryResponse,
  parseHealthResponse,
} from './validators';

/**
 * How many of the most recent alerts the alerts page asks for. The API's list
 * endpoint supports only this one parameter (`limit`: no offset, sorting or
 * filtering), so the page loads this many and filters them in the browser.
 */
export const ALERT_LIST_LIMIT = 200;

/** GET /health - confirms only that the API process answered. */
export async function getHealth(options?: RequestOptions): Promise<HealthResponse> {
  return parseHealthResponse(await requestJson('/health', options));
}

/** GET /api/v1/alerts/summary - statistics over persisted alert records. */
export async function getAlertSummary(options?: RequestOptions): Promise<AlertSummaryResponse> {
  return parseAlertSummaryResponse(await requestJson('/api/v1/alerts/summary', options));
}

export interface GetAlertsOptions extends RequestOptions {
  /** Maximum alerts to request, newest first. Defaults to ALERT_LIST_LIMIT. */
  limit?: number;
}

/** GET /api/v1/alerts - the most recently persisted alerts, newest first. */
export async function getAlerts(options: GetAlertsOptions = {}): Promise<AlertResponse[]> {
  const { limit = ALERT_LIST_LIMIT, ...requestOptions } = options;
  if (!Number.isSafeInteger(limit) || limit < 1) {
    throw new RangeError('limit must be a positive integer.');
  }
  return parseAlertListResponse(await requestJson(`/api/v1/alerts?limit=${limit}`, requestOptions));
}

/**
 * GET /api/v1/alerts/{alert_id} - one persisted alert.
 *
 * The ID is only ever interpolated as a validated positive integer, so a
 * value taken from the browser's address bar cannot change the request path.
 * An unknown ID rejects with an ApiError of kind "http" and status 404.
 */
export async function getAlert(alertId: number, options?: RequestOptions): Promise<AlertResponse> {
  if (!Number.isSafeInteger(alertId) || alertId < 1) {
    throw new RangeError('alertId must be a positive integer.');
  }
  return parseAlertResponse(await requestJson(`/api/v1/alerts/${alertId}`, options));
}
