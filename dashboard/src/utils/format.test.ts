import { describe, expect, it } from 'vitest';

import { formatCount, formatRatioAsPercent, formatTime, truncate } from './format';

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
