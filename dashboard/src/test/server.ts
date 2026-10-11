import { HttpResponse, http } from 'msw';
import { setupServer } from 'msw/node';

import { makeAlerts, makeSummary } from './fixtures';

/** Must match VITE_API_BASE_URL in vite.config.ts (test.env). */
export const API_ORIGIN = 'http://api.test';

export const HEALTH_URL = `${API_ORIGIN}/health`;
export const SUMMARY_URL = `${API_ORIGIN}/api/v1/alerts/summary`;
/** The list endpoint. MSW ignores the query string, so "?limit=200" still matches. */
export const ALERTS_URL = `${API_ORIGIN}/api/v1/alerts`;

/** One alert's endpoint. */
export const alertUrl = (id: number | string) => `${ALERTS_URL}/${id}`;

/**
 * Default handlers: a reachable API holding a small mixed store. Individual
 * tests replace them with server.use(...). Any request not handled here or
 * in a test fails the run (see setup.ts), so nothing can reach a real network.
 */
export const server = setupServer(
  http.get(HEALTH_URL, () => HttpResponse.json({ status: 'ok' })),
  http.get(SUMMARY_URL, () => HttpResponse.json(makeSummary())),
  http.get(ALERTS_URL, () => HttpResponse.json(makeAlerts())),
  // Registered after SUMMARY_URL on purpose: "/summary" must not be read as an alert ID.
  http.get(`${ALERTS_URL}/:alertId`, ({ params }) => {
    const alert = makeAlerts().find((candidate) => String(candidate.id) === params.alertId);
    return alert === undefined
      ? HttpResponse.json({ detail: 'Alert not found.' }, { status: 404 })
      : HttpResponse.json(alert);
  }),
);
