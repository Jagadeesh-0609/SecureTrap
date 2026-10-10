import { requestJson, type RequestOptions } from './client';
import type { AlertSummaryResponse, HealthResponse } from './types';
import { parseAlertSummaryResponse, parseHealthResponse } from './validators';

/** GET /health - confirms only that the API process answered. */
export async function getHealth(options?: RequestOptions): Promise<HealthResponse> {
  return parseHealthResponse(await requestJson('/health', options));
}

/** GET /api/v1/alerts/summary - statistics over persisted alert records. */
export async function getAlertSummary(options?: RequestOptions): Promise<AlertSummaryResponse> {
  return parseAlertSummaryResponse(await requestJson('/api/v1/alerts/summary', options));
}
