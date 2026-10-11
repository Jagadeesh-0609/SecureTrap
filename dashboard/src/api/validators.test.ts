import { describe, expect, it } from 'vitest';

import { makeAlert, makeAlerts, makeEmptySummary, makeSummary } from '../test/fixtures';
import { ApiError } from './client';
import {
  parseAlertListResponse,
  parseAlertResponse,
  parseAlertSummaryResponse,
  parseHealthResponse,
} from './validators';

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

const ALERT_FIELDS = [
  'id',
  'timestamp',
  'source_ip',
  'session_id',
  'protocol',
  'honeypot',
  'event_type',
  'command',
  'prediction',
  'score',
  'is_anomaly',
] as const;

describe('parseAlertResponse', () => {
  it('accepts a full, valid alert', () => {
    const alert = makeAlert();
    expect(parseAlertResponse(alert)).toEqual(alert);
  });

  it('returns a copy rather than the input object', () => {
    const input = makeAlert();
    expect(parseAlertResponse(input)).not.toBe(input);
  });

  it('accepts a non-anomalous record with an empty command and a positive score', () => {
    const alert = makeAlert({ prediction: 1, is_anomaly: false, command: '', score: 0.25 });
    expect(parseAlertResponse(alert)).toEqual(alert);
  });

  it('accepts a zero score and empty text fields', () => {
    const alert = makeAlert({ score: 0, session_id: '', protocol: '', honeypot: '' });
    expect(parseAlertResponse(alert)).toEqual(alert);
  });

  it('ignores fields it does not know, instead of copying them', () => {
    const parsed = parseAlertResponse({ ...makeAlert(), severity: 'critical', extra: { a: 1 } });
    expect(parsed).toEqual(makeAlert());
    expect(parsed).not.toHaveProperty('severity');
  });

  it('keeps hostile text as inert data', () => {
    const command = '<img src=x onerror=alert(1)>; $(rm -rf /)';
    expect(parseAlertResponse(makeAlert({ command })).command).toBe(command);
  });

  it.each([null, undefined, 'alert', 7, [makeAlert()]])('rejects the non-object %j', (value) => {
    expectInvalid(() => parseAlertResponse(value), 'response');
  });

  it.each(ALERT_FIELDS)('rejects an alert missing %s', (field) => {
    const body: Record<string, unknown> = { ...makeAlert() };
    delete body[field];
    expectInvalid(() => parseAlertResponse(body), field);
  });

  it.each([
    ['zero', 0],
    ['a negative number', -4],
    ['a fraction', 1.5],
    ['a numeric string', '7'],
    ['null', null],
    ['NaN', Number.NaN],
    ['beyond the safe integer range', 2 ** 53],
  ])('rejects %s as id', (_label, value) => {
    expectInvalid(() => parseAlertResponse({ ...makeAlert(), id: value }), 'id');
  });

  it.each(['timestamp', 'source_ip', 'session_id', 'protocol', 'honeypot', 'event_type', 'command'])(
    'rejects a non-string %s',
    (field) => {
      for (const value of [null, 5, true, ['x'], { a: 1 }]) {
        expectInvalid(() => parseAlertResponse({ ...makeAlert(), [field]: value }), field);
      }
    },
  );

  it.each([
    ['a numeric string', '-0.2'],
    ['null', null],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
  ])('rejects %s as score', (_label, value) => {
    expectInvalid(() => parseAlertResponse({ ...makeAlert(), score: value }), 'score');
  });

  it.each([
    ['a fraction', 0.5],
    ['a string', '-1'],
    ['null', null],
    ['NaN', Number.NaN],
  ])('rejects %s as prediction', (_label, value) => {
    expectInvalid(() => parseAlertResponse({ ...makeAlert(), prediction: value }), 'prediction');
  });

  it('keeps a whole-number prediction other than -1 or 1 as data, for the UI to label', () => {
    expect(parseAlertResponse(makeAlert({ prediction: 0 })).prediction).toBe(0);
  });

  it.each([
    ['the string "true"', 'true'],
    ['the number 1', 1],
    ['null', null],
  ])('rejects %s as is_anomaly', (_label, value) => {
    expectInvalid(() => parseAlertResponse({ ...makeAlert(), is_anomaly: value }), 'is_anomaly');
  });

  it('never repeats the offending value in its error', () => {
    const hostile = '<script>alert(1)</script>';
    try {
      parseAlertResponse({ ...makeAlert(), score: hostile });
      throw new Error('expected a rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      expect((error as ApiError).message).not.toContain('script');
    }
  });
});

describe('parseAlertListResponse', () => {
  it('accepts an empty list', () => {
    expect(parseAlertListResponse([])).toEqual([]);
  });

  it('accepts a list and keeps the API order (newest first)', () => {
    const alerts = makeAlerts();
    const parsed = parseAlertListResponse(alerts);
    expect(parsed).toEqual(alerts);
    expect(parsed.map((alert) => alert.id)).toEqual([5, 4, 3, 2, 1]);
  });

  it.each([null, undefined, {}, 'alerts', 5, { alerts: [] }, makeAlert()])('rejects the non-array %j', (value) => {
    expectInvalid(() => parseAlertListResponse(value), 'response');
  });

  it('rejects an element that is not an object, naming its position', () => {
    expectInvalid(() => parseAlertListResponse([makeAlert({ id: 1 }), 'nope']), 'alerts[1]');
  });

  it('names the position and field of a bad element', () => {
    const body = [makeAlert({ id: 3 }), makeAlert({ id: 2 }), { ...makeAlert({ id: 1 }), score: 'x' }];
    expectInvalid(() => parseAlertListResponse(body), 'alerts[2].score');
  });

  it('fails the whole response when one element is malformed', () => {
    const body = [makeAlert({ id: 2 }), { ...makeAlert({ id: 1 }), is_anomaly: 'yes' }];
    expect(() => parseAlertListResponse(body)).toThrow(ApiError);
  });

  it('rejects a repeated ID, since IDs identify rows and links', () => {
    expectInvalid(() => parseAlertListResponse([makeAlert({ id: 2 }), makeAlert({ id: 2 })]), 'alerts[1].id');
  });
});
