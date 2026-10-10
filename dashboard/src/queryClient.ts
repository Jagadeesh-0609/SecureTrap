import { QueryClient } from '@tanstack/react-query';

/**
 * The application's QueryClient.
 *
 * One quick retry keeps a transient blip from flashing an error, without
 * leaving an operator staring at a spinner while the API is genuinely down.
 */
export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: 1,
        retryDelay: 1_000,
        staleTime: 10_000,
        refetchOnWindowFocus: true,
      },
    },
  });
}
