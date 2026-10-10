import { useQuery } from '@tanstack/react-query';

import { getAlertSummary } from '../api/endpoints';
import type { AlertSummaryResponse } from '../api/types';
import { REFRESH_INTERVAL_MS } from '../config';

export const ALERT_SUMMARY_QUERY_KEY = ['alerts', 'summary'] as const;

/** Polls GET /api/v1/alerts/summary. Polling pauses while the tab is hidden. */
export function useAlertSummary() {
  return useQuery<AlertSummaryResponse, Error>({
    queryKey: ALERT_SUMMARY_QUERY_KEY,
    queryFn: ({ signal }) => getAlertSummary({ signal }),
    refetchInterval: REFRESH_INTERVAL_MS,
  });
}
