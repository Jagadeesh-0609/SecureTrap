import { ApiError } from '../api/client';
import type { AlertSummaryResponse } from '../api/types';

/**
 * Which of the overview's mutually exclusive screens to show.
 *
 *   loading      - first load in progress, nothing to show yet
 *   unavailable  - no data, and the API could not be reached (network/timeout)
 *   error        - no data, and the API answered badly (HTTP error / bad body)
 *   empty        - data received, but the alert store holds no records
 *   ready        - data received and there are records to show
 *
 * `empty` and `ready` carry `refreshError` when a later refresh failed; the
 * last good data is then still shown, marked as stale.
 */
export type OverviewViewState =
  | { kind: 'loading' }
  | { kind: 'unavailable'; error: ApiError }
  | { kind: 'error'; error: Error }
  | { kind: 'empty'; summary: AlertSummaryResponse; refreshError: Error | null }
  | { kind: 'ready'; summary: AlertSummaryResponse; refreshError: Error | null };

export interface OverviewQueryResult {
  data: AlertSummaryResponse | undefined;
  error: Error | null;
  isPending: boolean;
}

/** True when the failure means "could not reach the API" rather than "API misbehaved". */
export function isUnavailableError(error: unknown): error is ApiError {
  return error instanceof ApiError && (error.kind === 'network' || error.kind === 'timeout');
}

export function deriveOverviewState({ data, error, isPending }: OverviewQueryResult): OverviewViewState {
  if (data !== undefined) {
    return {
      kind: data.total_alerts === 0 ? 'empty' : 'ready',
      summary: data,
      refreshError: error,
    };
  }
  if (error !== null) {
    return isUnavailableError(error) ? { kind: 'unavailable', error } : { kind: 'error', error };
  }
  if (isPending) {
    return { kind: 'loading' };
  }
  // Defensive: no data, no error, not pending should not happen.
  return { kind: 'loading' };
}

/**
 * A short, safe description of a failure for display. Only messages this
 * code base wrote (ApiError) are shown; anything else gets a generic line so
 * unexpected internals never reach the page.
 */
export function describeError(error: Error | null): string {
  return error instanceof ApiError ? error.message : 'An unexpected error occurred.';
}
