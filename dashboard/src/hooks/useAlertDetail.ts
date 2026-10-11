import { useQuery } from '@tanstack/react-query';

import { getAlert } from '../api/endpoints';
import { ApiError } from '../api/client';
import type { AlertResponse } from '../api/types';

/**
 * The outcome of looking an alert up. "Not found" is a definite answer from
 * the API (HTTP 404), not a failure, so it is returned as data: it is not
 * retried and is never confused with the API being unreachable.
 */
export type AlertLookup = { found: true; alert: AlertResponse } | { found: false };

export const alertDetailQueryKey = (alertId: number | null) => ['alerts', 'detail', alertId] as const;

/**
 * GET /api/v1/alerts/{alert_id}. Pass null (an unusable ID from the address
 * bar) to make no request at all. A persisted alert does not change, so
 * there is no polling and no refetch on focus.
 */
export function useAlertDetail(alertId: number | null) {
  return useQuery<AlertLookup, Error>({
    queryKey: alertDetailQueryKey(alertId),
    enabled: alertId !== null,
    queryFn: async ({ signal }): Promise<AlertLookup> => {
      if (alertId === null) {
        throw new Error('No alert ID.');
      }
      try {
        return { found: true, alert: await getAlert(alertId, { signal }) };
      } catch (error) {
        if (error instanceof ApiError && error.kind === 'http' && error.status === 404) {
          return { found: false };
        }
        throw error;
      }
    },
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });
}
