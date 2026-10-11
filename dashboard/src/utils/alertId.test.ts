import { describe, expect, it } from 'vitest';

import { parseAlertIdParam } from './alertId';

describe('parseAlertIdParam', () => {
  it.each([
    ['1', 1],
    ['7', 7],
    ['42', 42],
    ['1000', 1000],
    ['9007199254740991', Number.MAX_SAFE_INTEGER],
  ])('reads %s as %s', (raw, expected) => {
    expect(parseAlertIdParam(raw)).toBe(expected);
  });

  it.each([
    ['undefined', undefined],
    ['an empty string', ''],
    ['zero', '0'],
    ['a leading zero', '01'],
    ['a negative number', '-3'],
    ['a fraction', '1.5'],
    ['an exponent', '1e3'],
    ['a plus sign', '+5'],
    ['hexadecimal', '0x10'],
    ['leading whitespace', ' 7'],
    ['trailing whitespace', '7 '],
    ['a trailing newline', '1\n'],
    ['letters', 'abc'],
    ['digits then letters', '12abc'],
    ['a path fragment', '1/../summary'],
    ['an encoded slash', '1%2F2'],
    ['a query string', '1?x=2'],
    ['full-width digits', '１２'],
    ['one past the largest safe integer', '9007199254740992'],
    ['a 17-digit number', '12345678901234567'],
    ['"NaN"', 'NaN'],
    ['"Infinity"', 'Infinity'],
  ])('rejects %s', (_label, raw) => {
    expect(parseAlertIdParam(raw)).toBeNull();
  });
});
