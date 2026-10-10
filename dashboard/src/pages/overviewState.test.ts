import { describe, expect, it } from 'vitest';

import { ApiError } from '../api/client';
import { makeAllFlaggedSummary, makeEmptySummary, makeSummary } from '../test/fixtures';
import { deriveOverviewState, describeError, isUnavailableError } from './overviewState';

const network = new ApiError('network', 'The API could not be reached.');
const timeout = new ApiError('timeout', 'The API did not respond in time.');
const http500 = new ApiError('http', 'The API responded with HTTP 500.', 500);
const invalid = new ApiError('invalid', 'Unexpected API response: "x" is missing or has the wrong type.');

describe('deriveOverviewState', () => {
  it('is loading while the first request is pending', () => {
    expect(deriveOverviewState({ data: undefined, error: null, isPending: true })).toEqual({
      kind: 'loading',
    });
  });

  it('is ready when there are persisted records', () => {
    const summary = makeSummary();
    expect(deriveOverviewState({ data: summary, error: null, isPending: false })).toEqual({
      kind: 'ready',
      summary,
      refreshError: null,
    });
  });

  it('is ready for a store holding only flagged records', () => {
    const summary = makeAllFlaggedSummary();
    expect(deriveOverviewState({ data: summary, error: null, isPending: false }).kind).toBe('ready');
  });

  it('is empty when the store holds no records', () => {
    const summary = makeEmptySummary();
    expect(deriveOverviewState({ data: summary, error: null, isPending: false })).toEqual({
      kind: 'empty',
      summary,
      refreshError: null,
    });
  });

  it.each([network, timeout])('is unavailable, with no data, for a %s failure', (error) => {
    expect(deriveOverviewState({ data: undefined, error, isPending: false })).toEqual({
      kind: 'unavailable',
      error,
    });
  });

  it.each([http500, invalid, new Error('boom')])('is an error, with no data, for %s', (error) => {
    expect(deriveOverviewState({ data: undefined, error, isPending: false })).toEqual({
      kind: 'error',
      error,
    });
  });

  it('keeps showing the last data, marked with the refresh error, when a refresh fails', () => {
    const summary = makeSummary();
    expect(deriveOverviewState({ data: summary, error: network, isPending: false })).toEqual({
      kind: 'ready',
      summary,
      refreshError: network,
    });
  });

  it('keeps an empty store visible, with the refresh error, when a refresh fails', () => {
    const summary = makeEmptySummary();
    expect(deriveOverviewState({ data: summary, error: http500, isPending: false })).toEqual({
      kind: 'empty',
      summary,
      refreshError: http500,
    });
  });
});

describe('isUnavailableError', () => {
  it('is true only for network and timeout failures', () => {
    expect(isUnavailableError(network)).toBe(true);
    expect(isUnavailableError(timeout)).toBe(true);
    expect(isUnavailableError(http500)).toBe(false);
    expect(isUnavailableError(invalid)).toBe(false);
    expect(isUnavailableError(new Error('x'))).toBe(false);
    expect(isUnavailableError(null)).toBe(false);
  });
});

describe('describeError', () => {
  it('shows messages this code base wrote', () => {
    expect(describeError(http500)).toBe('The API responded with HTTP 500.');
  });

  it('hides the message of any other error', () => {
    expect(describeError(new Error('secret internals at /srv/x'))).toBe('An unexpected error occurred.');
    expect(describeError(null)).toBe('An unexpected error occurred.');
  });
});
