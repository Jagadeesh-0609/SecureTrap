import { useQuery } from '@tanstack/react-query';

import { getHealth } from '../api/endpoints';
import type { HealthResponse } from '../api/types';
import { REFRESH_INTERVAL_MS } from '../config';

export const HEALTH_QUERY_KEY = ['health'] as const;

/** Polls GET /health. Polling pauses while the browser tab is hidden. */
export function useHealth() {
  return useQuery<HealthResponse, Error>({
    queryKey: HEALTH_QUERY_KEY,
    queryFn: ({ signal }) => getHealth({ signal }),
    refetchInterval: REFRESH_INTERVAL_MS,
  });
}
