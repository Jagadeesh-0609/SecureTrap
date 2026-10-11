import { describe, expect, it } from 'vitest';

import {
  formatAlertTimestamp,
  formatCount,
  formatRatioAsPercent,
  formatScore,
  formatTemplate,
  formatTime,
  parseAlertTimestamp,
  showInvisibleCharacters,
  truncate,
} from './format';

describe('formatCount', () => {
  it('formats small and large integers with grouping', () => {
    expect(formatCount(0)).toBe('0');
    expect(formatCount(7)).toBe('7');
    expect(formatCount(1234567)).toBe('1,234,567');
  });
});

describe('formatRatioAsPercent', () => {
  it.each([
    [0, '0%'],
    [0.4, '40%'],
    [0.5, '50%'],
    [1, '100%'],
    [0.33333, '33.3%'],
    [0.0004, '0%'],
  ])('formats the ratio %s as %s', (ratio, expected) => {
    expect(formatRatioAsPercent(ratio)).toBe(expected);
  });
});

describe('formatTime', () => {
  it('renders local 24-hour HH:MM:SS', () => {
    const epoch = new Date(2026, 9, 10, 3, 4, 5).getTime();
    expect(formatTime(epoch)).toBe('03:04:05');
  });
});

describe('truncate', () => {
  it('leaves short text alone', () => {
    expect(truncate('ok', 10)).toBe('ok');
    expect(truncate('1234567890', 10)).toBe('1234567890');
  });

  it('shortens long text and marks the cut', () => {
    expect(truncate('abcdefghijkl', 10)).toBe('abcdefghij…');
  });
});

describe('formatScore', () => {
  it.each([
    [-0.2361234, '-0.2361'],
    [0, '0.0000'],
    [0.5, '0.5000'],
    [0.12345, '0.1235'],
    [12.3456789, '12.3457'],
    [1234.5, '1,234.5000'],
  ])('formats %s as %s', (score, expected) => {
    expect(formatScore(score)).toBe(expected);
  });
});

describe('parseAlertTimestamp', () => {
  it('reads a UTC timestamp with fractional seconds', () => {
    expect(parseAlertTimestamp('2026-08-19T18:00:22.557428Z')?.toISOString()).toBe('2026-08-19T18:00:22.557Z');
  });

  it('reads a timestamp without fractional seconds', () => {
    expect(parseAlertTimestamp('2026-08-19T18:00:22Z')?.toISOString()).toBe('2026-08-19T18:00:22.000Z');
  });

  it('applies an explicit offset', () => {
    expect(parseAlertTimestamp('2026-08-19T23:30:00-05:00')?.toISOString()).toBe('2026-08-20T04:30:00.000Z');
    expect(parseAlertTimestamp('2026-08-19T01:30:00+05:30')?.toISOString()).toBe('2026-08-18T20:00:00.000Z');
  });

  it('accepts 29 February in a leap year', () => {
    expect(parseAlertTimestamp('2028-02-29T00:00:00Z')?.toISOString()).toBe('2028-02-29T00:00:00.000Z');
  });

  it.each([
    ['a timestamp with no offset (would be read as local time)', '2026-08-19T18:00:22'],
    ['a date only', '2026-08-19'],
    ['a space instead of T', '2026-08-19 18:00:22Z'],
    ['a non-existent day', '2026-02-31T00:00:00Z'],
    ['29 February in a non-leap year', '2026-02-29T00:00:00Z'],
    ['day zero', '2026-08-00T00:00:00Z'],
    ['month 13', '2026-13-01T00:00:00Z'],
    ['hour 24', '2026-08-19T24:00:00Z'],
    ['minute 60', '2026-08-19T18:60:00Z'],
    ['second 60', '2026-08-19T18:00:60Z'],
    ['an empty string', ''],
    ['free text', 'yesterday'],
    ['surrounding whitespace', ' 2026-08-19T18:00:22Z '],
    ['a trailing newline', '2026-08-19T18:00:22Z\n'],
  ])('returns null for %s', (_label, raw) => {
    expect(parseAlertTimestamp(raw)).toBeNull();
  });
});

describe('formatAlertTimestamp', () => {
  it('writes a UTC timestamp as readable UTC text', () => {
    expect(formatAlertTimestamp('2026-08-19T18:00:22.557428Z')).toBe('2026-08-19 18:00:22 UTC');
  });

  it('converts an offset timestamp to UTC', () => {
    expect(formatAlertTimestamp('2026-08-19T23:30:00-05:00')).toBe('2026-08-20 04:30:00 UTC');
  });

  it('pads single-digit fields', () => {
    expect(formatAlertTimestamp('2026-01-02T03:04:05Z')).toBe('2026-01-02 03:04:05 UTC');
  });

  it('returns a value it cannot read exactly as given', () => {
    expect(formatAlertTimestamp('2026-02-31T00:00:00Z')).toBe('2026-02-31T00:00:00Z');
    expect(formatAlertTimestamp('not a time')).toBe('not a time');
    expect(formatAlertTimestamp('')).toBe('');
  });
});

describe('formatTemplate', () => {
  it('fills placeholders with strings and numbers', () => {
    expect(formatTemplate('{shown} of {count}', { shown: 3, count: '12' })).toBe('3 of 12');
  });

  it('fills a repeated placeholder everywhere', () => {
    expect(formatTemplate('{n}-{n}', { n: 7 })).toBe('7-7');
  });

  it('leaves a placeholder it has no value for', () => {
    expect(formatTemplate('{a} {b}', { a: 'x' })).toBe('x {b}');
  });

  it('inserts values literally, including replacement-pattern characters', () => {
    expect(formatTemplate('[{v}]', { v: '$& $1 $$' })).toBe('[$& $1 $$]');
  });
});

describe('showInvisibleCharacters', () => {
  it('leaves ordinary text alone, including non-Latin text and emoji', () => {
    for (const text of ['', 'wget http://x.test/a.sh', 'ls -la\n\tcat x', 'héllo wörld', 'ключ 鍵 مفتاح', 'ok 👍']) {
      expect(showInvisibleCharacters(text)).toBe(text);
    }
  });

  it('writes a right-to-left override as a visible marker', () => {
    expect(showInvisibleCharacters('echo \u202Eevil\u202C done')).toBe('echo [U+202E]evil[U+202C] done');
  });

  it.each([
    ['U+061C', '\u061C'],
    ['U+200B', '\u200B'],
    ['U+200C', '\u200C'],
    ['U+200D', '\u200D'],
    ['U+200E', '\u200E'],
    ['U+200F', '\u200F'],
    ['U+202A', '\u202A'],
    ['U+202B', '\u202B'],
    ['U+202C', '\u202C'],
    ['U+202D', '\u202D'],
    ['U+202E', '\u202E'],
    ['U+2060', '\u2060'],
    ['U+2066', '\u2066'],
    ['U+2067', '\u2067'],
    ['U+2068', '\u2068'],
    ['U+2069', '\u2069'],
    ['U+FEFF', '\uFEFF'],
  ])('marks %s', (code, character) => {
    expect(showInvisibleCharacters(`a${character}b`)).toBe(`a[${code}]b`);
  });

  it('marks every occurrence', () => {
    expect(showInvisibleCharacters('\u200B\u200B')).toBe('[U+200B][U+200B]');
  });

  it('makes two commands that differ only by a hidden character look different', () => {
    expect(showInvisibleCharacters('rm\u200B -rf')).not.toBe(showInvisibleCharacters('rm -rf'));
  });
});
