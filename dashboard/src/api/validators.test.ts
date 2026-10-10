import { describe, expect, it } from 'vitest';

import { makeEmptySummary, makeSummary } from '../test/fixtures';
import { ApiError } from './client';
import { parseAlertSummaryResponse, parseHealthResponse } from './validators';

function expectInvalid(action: () => unknown, field: string) {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).kind).toBe('invalid');
    expect((error as ApiError).message).toContain(field);
    return;
  }
  throw new Error(`Expected "${field}" to be rejected, but parsing succeeded.`);
}

describe('parseHealthResponse', () => {
  it('accepts a status string', () => {
    expect(parseHealthResponse({ status: 'ok' })).toEqual({ status: 'ok' });
  });

  it('keeps an unexpected status string as plain data', () => {
    expect(parseHealthResponse({ status: '<b>x</b>' })).toEqual({ status: '<b>x</b>' });
  });

  it.each([null, undefined, 'ok', 42, ['ok']])('rejects the non-object %j', (value) => {
    expectInvalid(() => parseHealthResponse(value), 'response');
  });

  it.each([{}, { status: 1 }, { status: null }])('rejects a bad status in %j', (value) => {
    expectInvalid(() => parseHealthResponse(value), 'status');
  });
});

describe('parseAlertSummaryResponse', () => {
  it('accepts a full, valid summary', () => {
    const summary = makeSummary();
    expect(parseAlertSummaryResponse(summary)).toEqual(summary);
  });

  it('accepts an empty store with null score statistics', () => {
    expect(parseAlertSummaryResponse(makeEmptySummary())).toEqual(makeEmptySummary());
  });

  it('accepts the 0.0 and 1.0 boundaries of the anomaly rate', () => {
    expect(parseAlertSummaryResponse(makeSummary({ anomaly_rate: 0 })).anomaly_rate).toBe(0);
    expect(parseAlertSummaryResponse(makeSummary({ anomaly_rate: 1 })).anomaly_rate).toBe(1);
  });

  it('returns a copy rather than the input object', () => {
    const input = makeSummary();
    expect(parseAlertSummaryResponse(input)).not.toBe(input);
  });

  it.each([null, undefined, 'summary', 7, [makeSummary()]])('rejects the non-object %j', (value) => {
    expectInvalid(() => parseAlertSummaryResponse(value), 'response');
  });

  it.each([
    'total_alerts',
    'anomaly_count',
    'normal_count',
    'anomaly_rate',
    'event_type_counts',
    'source_ip_counts',
    'score_min',
    'score_max',
    'score_average',
  ])('rejects a response missing %s', (field) => {
    const body: Record<string, unknown> = { ...makeSummary() };
    delete body[field];
    expectInvalid(() => parseAlertSummaryResponse(body), field);
  });

  it.each([
    ['a numeric string', '5'],
    ['null', null],
    ['a negative number', -1],
    ['a fraction', 1.5],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
  ])('rejects %s as total_alerts', (_label, value) => {
    expectInvalid(() => parseAlertSummaryResponse({ ...makeSummary(), total_alerts: value }), 'total_alerts');
  });

  it.each([-0.1, 1.5, Number.NaN, '0.4', null])('rejects %j as anomaly_rate', (value) => {
    expectInvalid(() => parseAlertSummaryResponse({ ...makeSummary(), anomaly_rate: value }), 'anomaly_rate');
  });

  it.each([
    ['a string', '-0.5'],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['undefined', undefined],
  ])('rejects %s as score_min', (_label, value) => {
    expectInvalid(() => parseAlertSummaryResponse({ ...makeSummary(), score_min: value }), 'score_min');
  });

  it.each([
    ['an array', [1, 2]],
    ['null', null],
    ['a string', 'x'],
    ['a map with a negative count', { a: -1 }],
    ['a map with a string count', { a: '1' }],
    ['a map with a fractional count', { a: 0.5 }],
  ])('rejects %s as event_type_counts', (_label, value) => {
    expectInvalid(
      () => parseAlertSummaryResponse({ ...makeSummary(), event_type_counts: value }),
      'event_type_counts',
    );
  });

  it('keeps hostile map keys as inert data and does not touch the prototype', () => {
    const hostile = JSON.parse(
      '{"__proto__": 3, "<img src=x onerror=alert(1)>": 2, "constructor": 1}',
    ) as Record<string, number>;

    const parsed = parseAlertSummaryResponse({ ...makeSummary(), source_ip_counts: hostile });

    expect(Object.keys(parsed.source_ip_counts).sort()).toEqual(
      ['<img src=x onerror=alert(1)>', '__proto__', 'constructor'].sort(),
    );
    expect(Object.getPrototypeOf(parsed.source_ip_counts)).toBe(Object.prototype);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});
