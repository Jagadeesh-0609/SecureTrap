/**
 * All user-facing wording that carries SecureTrap's data semantics lives here,
 * in one reviewable place.
 *
 * The rules this wording follows (enforced by copy.test.ts):
 *   - figures describe PERSISTED alert records, never all traffic or all model
 *     predictions;
 *   - an "anomaly" is a statistical outlier, never a confirmed attack;
 *   - anomaly scores are never presented as probabilities or confidence;
 *   - a reachable /health endpoint never implies a healthy detection system.
 *
 * Other source files must not use that vocabulary themselves; they take their
 * text from here.
 */
export const COPY = {
  brand: { name: 'SecureTrap', product: 'Dashboard' },

  footer:
    'Read-only view of the SecureTrap API. An anomaly is a statistical outlier flagged by an unsupervised model, not a confirmed attack.',

  nav: { overview: 'Overview', alerts: 'Alerts', soon: 'Soon' },

  scope: {
    heading: 'What these figures describe',
    persisted:
      'Every figure on this page describes alert records persisted in the SecureTrap alert store. It is not a summary of all traffic, and not a count of every prediction the model has made.',
    semantics:
      'An "anomaly" is a statistical outlier flagged by an unsupervised IsolationForest model. It is not a confirmed attack. Anomaly scores are not probabilities or confidence values.',
  },

  overview: {
    title: 'Overview',
    summaryHeading: 'Persisted alert summary',
    refresh: 'Refresh',
    refreshing: 'Refreshing…',
    updated: 'Updated',
    autoRefresh: 'Refreshes automatically every 30 seconds while this tab is visible.',
  },

  cards: {
    total: {
      label: 'Persisted alerts',
      caption: 'Alert records currently stored.',
    },
    anomalies: {
      label: 'Persisted anomalies',
      caption: 'Stored records flagged as statistical outliers. Not confirmed attacks.',
    },
    normal: {
      label: 'Persisted non-anomalous records',
      caption:
        'Stored records not flagged as outliers. Not the number of normal predictions the model made.',
    },
    rate: {
      label: 'Anomaly share of persisted records',
      caption: 'Persisted anomalies divided by persisted alerts. Not the share of all model predictions.',
    },
    allFlaggedNote:
      'No non-anomalous records are persisted, so every stored record is flagged and the share above is necessarily 100%. This describes what was persisted; it says nothing about how many normal events the model saw.',
  },

  states: {
    loading: 'Loading alert summary…',
    empty: {
      title: 'No alerts persisted yet',
      body: 'The alert store has no records, so there is nothing to summarise.',
      detail:
        'This dashboard cannot tell "nothing has been flagged" apart from "the detection service is not running": no API endpoint reports detector activity.',
    },
    unavailable: {
      title: 'Cannot reach the SecureTrap API',
      body: 'The request did not complete, so the summary could not be loaded.',
      hints: [
        'Check that the API process is running.',
        "Check that this dashboard's origin is allowed by the API's SECURETRAP_CORS_ORIGINS setting. A browser reports a CORS block in the same way as a network failure.",
        'Check that VITE_API_BASE_URL points at the API.',
      ],
      configured: 'Requests are sent to:',
    },
    httpError: {
      title: 'The API returned an error',
      body: 'The summary could not be loaded. This is a failure on the API side; trying again may help.',
    },
    invalidResponse: {
      title: 'Unexpected API response',
      body: 'The API replied, but not in the format this dashboard expects. The dashboard and the API may be out of sync.',
    },
    stale: {
      lead: 'Showing the last data received at',
      reason: 'The latest refresh failed:',
    },
    retry: 'Try again',
    config: {
      title: 'Dashboard configuration error',
      lead: 'VITE_API_BASE_URL',
      fix: 'Fix the value and restart the dev server or rebuild the dashboard.',
    },
    notFound: { title: 'Page not found', body: 'There is nothing at this address.', back: 'Back to the overview' },
  },

  apiStatus: {
    checking: 'Checking API…',
    checkingDetail: 'Waiting for the API to answer its /health check.',
    reachable: 'API reachable',
    reachableDetail:
      'The API process answered its /health check. This does not verify the database, the detection service, or the honeypot.',
    unreachable: 'API unreachable',
    unreachableDetail: 'The /health request did not complete.',
    httpErrorDetail: 'The /health request completed, but the API answered with an error status.',
    unexpected: 'API responded',
    unexpectedDetail: 'The /health check returned a status other than "ok".',
    invalidDetail: 'The /health response was not in the expected format.',
  },
} as const;
