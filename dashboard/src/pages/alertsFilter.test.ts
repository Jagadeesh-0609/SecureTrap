import { describe, expect, it } from 'vitest';

import type { AlertResponse } from '../api/types';
import { makeAlert, makeAlerts } from '../test/fixtures';
import {
  NO_FILTERS,
  buildSearchIndex,
  distinctEventTypes,
  filterAlerts,
  hasActiveFilters,
  hasBothFlags,
  readFilters,
  toFlagFilter,
  writeFilters,
  type AlertFilters,
} from './alertsFilter';

function run(filters: Partial<AlertFilters>, alerts: readonly AlertResponse[] = makeAlerts()): number[] {
  return filterAlerts(buildSearchIndex(alerts), { ...NO_FILTERS, ...filters }).map((alert) => alert.id);
}

describe('filterAlerts', () => {
  it('returns every alert, in the same order, when nothing is filtered', () => {
    expect(run({})).toEqual([5, 4, 3, 2, 1]);
  });

  it('matches upper-case data with a lower-case search, and the reverse', () => {
    const alerts = [
      makeAlert({ id: 2, command: 'WGET HTTP://X.TEST/Bot.sh', event_type: 'Cowrie.Command.INPUT' }),
      makeAlert({ id: 1, command: 'ls', source_ip: 'FE80::1', event_type: 'cowrie.login.failed' }),
    ];
    expect(run({ query: 'wget' }, alerts)).toEqual([2]);
    expect(run({ query: 'WGET' }, alerts)).toEqual([2]);
    expect(run({ query: 'bot.SH' }, alerts)).toEqual([2]);
    expect(run({ query: 'cowrie.command.input' }, alerts)).toEqual([2]);
    expect(run({ query: 'fe80::1' }, alerts)).toEqual([1]);
  });

  it('treats a blank or whitespace-only search as no search', () => {
    expect(run({ query: '' })).toEqual([5, 4, 3, 2, 1]);
    expect(run({ query: '   \t ' })).toEqual([5, 4, 3, 2, 1]);
  });

  it('searches case-insensitively', () => {
    expect(run({ query: 'WGET' })).toEqual([5]);
    expect(run({ query: 'wget' })).toEqual([5]);
    expect(run({ query: 'CoWrIe.LoGiN' })).toEqual([4, 1]);
  });

  it.each([
    ['the command', 'etc/passwd', [2]],
    ['the source IP', '10.0.0.3', [3]],
    ['the session ID', 'sess-0004', [4]],
    ['the event type', 'login.failed', [4]],
    ['the alert ID', '4', [4]],
    ['the timestamp', '18:02:00', [2]],
    ['the protocol', 'ssh', [5, 4, 3, 2, 1]],
    ['the honeypot', 'cowrie', [5, 4, 3, 2, 1]],
  ])('searches %s', (_label, query, expected) => {
    expect(run({ query })).toEqual(expected);
  });

  it('requires every word to match, in any order', () => {
    expect(run({ query: '10.0.0.1 wget' })).toEqual([5]);
    expect(run({ query: 'wget 10.0.0.1' })).toEqual([5]);
    expect(run({ query: '10.0.0.1 uname' })).toEqual([]);
  });

  it('ignores extra whitespace between words', () => {
    expect(run({ query: '  10.0.0.1    passwd ' })).toEqual([2]);
  });

  it('matches nothing for text that is in no alert', () => {
    expect(run({ query: 'zzz-not-there' })).toEqual([]);
  });

  it('treats regular-expression characters as plain text', () => {
    expect(run({ query: '.*' })).toEqual([]);
    expect(run({ query: '(' })).toEqual([]);
    expect(run({ query: '10.0.0.x' })).toEqual([]);
    expect(run({ query: '[' })).toEqual([]);
  });

  it('filters by exact event type', () => {
    expect(run({ eventType: 'cowrie.command.input' })).toEqual([5, 3, 2]);
    expect(run({ eventType: 'cowrie.login.failed' })).toEqual([4]);
    expect(run({ eventType: 'cowrie' })).toEqual([]);
  });

  it('filters by anomaly flag', () => {
    expect(run({ flag: 'flagged' })).toEqual([5, 2]);
    expect(run({ flag: 'notFlagged' })).toEqual([4, 3, 1]);
    expect(run({ flag: 'all' })).toEqual([5, 4, 3, 2, 1]);
  });

  it('combines search, event type and flag', () => {
    expect(run({ query: '10.0.0.1', eventType: 'cowrie.command.input', flag: 'flagged' })).toEqual([5, 2]);
    expect(run({ query: '10.0.0.1', eventType: 'cowrie.command.input', flag: 'notFlagged' })).toEqual([]);
  });

  it('does not change or reorder the loaded alerts', () => {
    const alerts = makeAlerts();
    const before = JSON.stringify(alerts);
    run({ query: 'wget', flag: 'flagged' }, alerts);
    expect(JSON.stringify(alerts)).toBe(before);
  });

  it('copes with a field that is missing at runtime', () => {
    const broken = { ...makeAlert({ id: 9 }), command: undefined, session_id: null } as unknown as AlertResponse;
    expect(() => run({ query: 'x' }, [broken])).not.toThrow();
    expect(run({ query: '10.0.0.1' }, [broken])).toEqual([9]);
    expect(run({ query: 'undefined' }, [broken])).toEqual([]);
    expect(run({ query: 'null' }, [broken])).toEqual([]);
  });

  it('copes with an empty list', () => {
    expect(run({ query: 'x', flag: 'flagged', eventType: 'y' }, [])).toEqual([]);
  });
});

describe('distinctEventTypes', () => {
  it('lists each event type once, sorted', () => {
    expect(distinctEventTypes(makeAlerts())).toEqual([
      'cowrie.command.input',
      'cowrie.login.failed',
      'cowrie.login.success',
    ]);
  });

  it('is empty for no alerts', () => {
    expect(distinctEventTypes([])).toEqual([]);
  });
});

describe('hasBothFlags', () => {
  it('is true when flagged and unflagged records are both present', () => {
    expect(hasBothFlags(makeAlerts())).toBe(true);
  });

  it('is false when every record has the same flag', () => {
    expect(hasBothFlags([makeAlert({ id: 1 }), makeAlert({ id: 2 })])).toBe(false);
    expect(hasBothFlags([makeAlert({ id: 1, is_anomaly: false }), makeAlert({ id: 2, is_anomaly: false })])).toBe(false);
  });

  it('is false for no alerts', () => {
    expect(hasBothFlags([])).toBe(false);
  });
});

describe('hasActiveFilters', () => {
  it('is false for the defaults and for a blank search', () => {
    expect(hasActiveFilters(NO_FILTERS)).toBe(false);
    expect(hasActiveFilters({ ...NO_FILTERS, query: '   ' })).toBe(false);
  });

  it.each([{ query: 'x' }, { eventType: 'cowrie.login.failed' }, { flag: 'flagged' as const }])(
    'is true for %j',
    (changes) => {
      expect(hasActiveFilters({ ...NO_FILTERS, ...changes })).toBe(true);
    },
  );
});

describe('toFlagFilter', () => {
  it('accepts the two real choices and maps anything else to "all"', () => {
    expect(toFlagFilter('flagged')).toBe('flagged');
    expect(toFlagFilter('notFlagged')).toBe('notFlagged');
    expect(toFlagFilter('all')).toBe('all');
    expect(toFlagFilter('attack')).toBe('all');
    expect(toFlagFilter('')).toBe('all');
    expect(toFlagFilter(null)).toBe('all');
  });
});

describe('readFilters / writeFilters', () => {
  it('reads filters from a query string', () => {
    expect(readFilters(new URLSearchParams('q=wget&type=cowrie.command.input&flag=flagged'))).toEqual({
      query: 'wget',
      eventType: 'cowrie.command.input',
      flag: 'flagged',
    });
  });

  it('uses the defaults when the query string has nothing', () => {
    expect(readFilters(new URLSearchParams(''))).toEqual(NO_FILTERS);
  });

  it('ignores an unknown flag value', () => {
    expect(readFilters(new URLSearchParams('flag=bogus')).flag).toBe('all');
  });

  it('caps an overlong search', () => {
    expect(readFilters(new URLSearchParams({ q: 'a'.repeat(500) })).query).toHaveLength(200);
  });

  it('writes only the non-default filters', () => {
    expect(writeFilters(NO_FILTERS).toString()).toBe('');
    expect(writeFilters({ ...NO_FILTERS, query: 'wget' }).toString()).toBe('q=wget');
    expect(writeFilters({ query: 'a b', eventType: 'cowrie.login.failed', flag: 'notFlagged' }).toString()).toBe(
      'q=a+b&type=cowrie.login.failed&flag=notFlagged',
    );
  });

  it('round-trips awkward text', () => {
    const filters: AlertFilters = { query: 'a&b=c #d %e / ü', eventType: 'x y', flag: 'flagged' };
    expect(readFilters(new URLSearchParams(writeFilters(filters).toString()))).toEqual(filters);
  });
});
