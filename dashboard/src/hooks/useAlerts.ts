import { useQuery } from '@tanstack/react-query';

import { ALERT_LIST_LIMIT, getAlerts } from '../api/endpoints';
import type { AlertResponse } from '../api/types';

export const ALERT_LIST_QUERY_KEY = ['alerts', 'list', ALERT_LIST_LIMIT] as const;

/**
 * GET /api/v1/alerts: the most recent persisted alerts.
 *
 * Loaded once when the page opens and again only when asked (the Refresh
 * button). It does not poll, and does not refetch on window focus or
 * reconnect, so rows never move while someone is reading or filtering them.
 */
export function useAlerts() {
  return useQuery<AlertResponse[], Error>({
    queryKey: ALERT_LIST_QUERY_KEY,
    queryFn: ({ signal }) => getAlerts({ signal }),
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });
}
