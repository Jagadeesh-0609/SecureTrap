import type { ApiError } from '../api/client';
import type { AlertResponse } from '../api/types';
import { isUnavailableError } from './overviewState';

/**
 * Which of the alerts page's mutually exclusive screens to show.
 *
 *   loading      - first load in progress, nothing to show yet
 *   unavailable  - no data, and the API could not be reached (network/timeout)
 *   error        - no data, and the API answered badly (HTTP error / bad body)
 *   empty        - data received, but no alerts are persisted
 *   ready        - data received and there are alerts to show
 *
 * `empty` and `ready` carry `refreshError` when a later refresh failed; the
 * last good data is then still shown, marked as stale.
 */
export type AlertsViewState =
  | { kind: 'loading' }
  | { kind: 'unavailable'; error: ApiError }
  | { kind: 'error'; error: Error }
  | { kind: 'empty'; refreshError: Error | null }
  | { kind: 'ready'; alerts: AlertResponse[]; refreshError: Error | null };

export interface AlertsQueryResult {
  data: AlertResponse[] | undefined;
  error: Error | null;
}

export function deriveAlertsState({ data, error }: AlertsQueryResult): AlertsViewState {
  if (data !== undefined) {
    return data.length === 0
      ? { kind: 'empty', refreshError: error }
      : { kind: 'ready', alerts: data, refreshError: error };
  }
  if (error !== null) {
    return isUnavailableError(error) ? { kind: 'unavailable', error } : { kind: 'error', error };
  }
  return { kind: 'loading' };
}
