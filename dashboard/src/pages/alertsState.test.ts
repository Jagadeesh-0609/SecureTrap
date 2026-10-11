import { describe, expect, it } from 'vitest';

import { ApiError } from '../api/client';
import { makeAlerts } from '../test/fixtures';
import { deriveAlertsState } from './alertsState';

const network = new ApiError('network', 'The API could not be reached.');
const timeout = new ApiError('timeout', 'The API did not respond in time.');
const http500 = new ApiError('http', 'The API responded with HTTP 500.', 500);
const invalid = new ApiError('invalid', 'Unexpected API response: "response" is missing or has the wrong type.');

describe('deriveAlertsState', () => {
  it('is loading while there is neither data nor an error', () => {
    expect(deriveAlertsState({ data: undefined, error: null })).toEqual({ kind: 'loading' });
  });

  it('is ready when alerts were returned', () => {
    const alerts = makeAlerts();
    expect(deriveAlertsState({ data: alerts, error: null })).toEqual({ kind: 'ready', alerts, refreshError: null });
  });

  it('is empty when the list is empty', () => {
    expect(deriveAlertsState({ data: [], error: null })).toEqual({ kind: 'empty', refreshError: null });
  });

  it.each([network, timeout])('is unavailable, with no data, for a %s error', (error) => {
    expect(deriveAlertsState({ data: undefined, error })).toEqual({ kind: 'unavailable', error });
  });

  it.each([http500, invalid, new Error('boom')])('is an error, with no data, for %s', (error) => {
    expect(deriveAlertsState({ data: undefined, error })).toEqual({ kind: 'error', error });
  });

  it('keeps showing the last alerts, with the refresh error, when a refresh fails', () => {
    const alerts = makeAlerts();
    expect(deriveAlertsState({ data: alerts, error: network })).toEqual({
      kind: 'ready',
      alerts,
      refreshError: network,
    });
  });

  it('keeps showing an empty list, with the refresh error, when a refresh fails', () => {
    expect(deriveAlertsState({ data: [], error: http500 })).toEqual({ kind: 'empty', refreshError: http500 });
  });
});
