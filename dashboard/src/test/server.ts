import { HttpResponse, http } from 'msw';
import { setupServer } from 'msw/node';

import { makeSummary } from './fixtures';

/** Must match VITE_API_BASE_URL in vite.config.ts (test.env). */
export const API_ORIGIN = 'http://api.test';

export const HEALTH_URL = `${API_ORIGIN}/health`;
export const SUMMARY_URL = `${API_ORIGIN}/api/v1/alerts/summary`;

/**
 * Default handlers: a reachable API holding a small mixed store. Individual
 * tests replace them with server.use(...). Any request not handled here or
 * in a test fails the run (see setup.ts), so nothing can reach a real network.
 */
export const server = setupServer(
  http.get(HEALTH_URL, () => HttpResponse.json({ status: 'ok' })),
  http.get(SUMMARY_URL, () => HttpResponse.json(makeSummary())),
);
