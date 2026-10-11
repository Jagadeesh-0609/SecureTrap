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

  alerts: {
    title: 'Alerts',
    intro:
      'Persisted alert records, newest first by when each was persisted (not necessarily by event time).',
    refreshHint: 'Loaded when you open this page. Use Refresh to check for newer alerts.',
    semantics:
      'A flagged record is a statistical outlier from an unsupervised model, not a confirmed attack. Scores are not probabilities or confidence values.',
    countOne: '{count} alert returned',
    countMany: '{count} alerts returned',
    showingOne: 'Showing {shown} of {count} returned alert',
    showingMany: 'Showing {shown} of {count} returned alerts',
    limitNote:
      'The API was asked for the {limit} most recently persisted alerts. Older alerts, if any, are not loaded here.',
    filters: {
      label: 'Filter alerts',
      search: 'Search',
      searchHint:
        'Case-insensitive. Looks through ID, time, source IP, session, protocol, honeypot, event type and command. Every word must match.',
      searchPlaceholder: 'IP, event type, command…',
      eventType: 'Event type',
      allEventTypes: 'All event types',
      flag: 'Anomaly flag',
      allFlags: 'All records',
      flagged: 'Flagged as anomaly',
      notFlagged: 'Not flagged',
      clear: 'Clear filters',
    },
    noResults: {
      title: 'No alerts match the filters',
      body: 'None of the {count} loaded alerts match. Change the search or clear the filters.',
    },
    table: {
      caption: 'Persisted alerts, newest first',
      scrollLabel: 'Alerts table. Scrolls sideways on narrow screens.',
      id: 'ID',
      time: 'Time (UTC)',
      eventType: 'Event type',
      sourceIp: 'Source IP',
      command: 'Command',
      score: 'Score',
      flag: 'Anomaly flag',
      open: 'Open alert',
      flagged: 'Flagged',
      notFlagged: 'Not flagged',
      noCommand: '(none)',
    },
    states: {
      loading: 'Loading alerts…',
      empty: {
        title: 'No alerts persisted yet',
        body: 'The alert store has no records.',
      },
      unavailableBody: 'The request did not complete, so alerts could not be loaded.',
      httpErrorBody:
        'Alerts could not be loaded. This is a failure on the API side; trying again may help.',
    },
  },

  alertDetail: {
    title: 'Alert',
    back: 'Back to alerts',
    semantics:
      'An anomaly flag means the model marked this record as a statistical outlier. It is not a confirmed attack.',
    fields: {
      id: 'Alert ID',
      time: 'Time (UTC)',
      timestamp: 'Recorded timestamp',
      sourceIp: 'Source IP',
      sessionId: 'Session ID',
      protocol: 'Protocol',
      honeypot: 'Honeypot',
      eventType: 'Event type',
      command: 'Command',
      prediction: 'Model prediction',
      score: 'Anomaly score',
      flag: 'Anomaly flag',
    },
    commandNote:
      'Shown as recorded. It comes from the honeypot session and is untrusted text. Invisible direction and zero-width characters are shown as [U+XXXX] markers.',
    noCommand: '(none)',
    predictionOutlier: '-1 (outlier)',
    predictionInlier: '1 (inlier)',
    predictionOther: '{value} (not a value this dashboard recognises)',
    scoreNote:
      'Raw IsolationForest decision score; lower values are more outlying. Scores are not probabilities or confidence values.',
    flagged: 'Flagged as an anomaly (statistical outlier)',
    notFlagged: 'Not flagged as an anomaly',
    states: {
      loading: 'Loading alert…',
      notFound: {
        title: 'Alert not found',
        body: 'No persisted alert has the ID {id}.',
      },
      invalidId: {
        title: 'Invalid alert ID',
        body: 'Alert IDs are positive whole numbers. Check the address and try again.',
      },
      unavailableBody: 'The request did not complete, so the alert could not be loaded.',
      httpErrorBody:
        'The alert could not be loaded. This is a failure on the API side; trying again may help.',
    },
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
