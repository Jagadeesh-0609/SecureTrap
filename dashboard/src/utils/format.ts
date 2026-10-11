const NUMBER_LOCALE = 'en-US';

const countFormatter = new Intl.NumberFormat(NUMBER_LOCALE);
const percentFormatter = new Intl.NumberFormat(NUMBER_LOCALE, {
  style: 'percent',
  maximumFractionDigits: 1,
});
const scoreFormatter = new Intl.NumberFormat(NUMBER_LOCALE, {
  minimumFractionDigits: 4,
  maximumFractionDigits: 4,
});
const timeFormatter = new Intl.DateTimeFormat('en-GB', {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
});

/** 1234567 -> "1,234,567". */
export function formatCount(value: number): string {
  return countFormatter.format(value);
}

/** A 0.0-1.0 ratio -> "40%" / "33.3%" / "100%". */
export function formatRatioAsPercent(ratio: number): string {
  return percentFormatter.format(ratio);
}

/** Epoch milliseconds -> local "HH:MM:SS" (24-hour). */
export function formatTime(epochMs: number): string {
  return timeFormatter.format(new Date(epochMs));
}

/**
 * Shorten text that came from the network so it cannot blow up the layout.
 * Display only: the value is still rendered as a text node by React.
 */
export function truncate(text: string, maxLength: number): string {
  return text.length <= maxLength ? text : `${text.slice(0, maxLength)}…`;
}

// Characters that change the order text is drawn in (direction controls) or
// that draw nothing at all (zero-width characters and the byte-order mark).
const INVISIBLE_FORMATTING = /[\u061C\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]/g;

/**
 * Make invisible formatting characters visible, as "[U+202E]" markers.
 *
 * Text from honeypot sessions is controlled by whoever connected. A right-to-left
 * override inside a command can make the browser draw "evil" as "live", and
 * zero-width characters can make two different commands look identical. Showing
 * the character's code point instead keeps what an analyst reads honest. Display
 * only: the stored value is untouched.
 */
export function showInvisibleCharacters(text: string): string {
  return text.replace(INVISIBLE_FORMATTING, (character) => {
    const codePoint = (character.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0');
    return `[U+${codePoint}]`;
  });
}

/** An anomaly score -> fixed four decimals, e.g. -0.2361. */
export function formatScore(value: number): string {
  return scoreFormatter.format(value);
}

// ISO 8601 date-time that states its own offset ("Z" or "+05:30").
const ZONED_ISO_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

/**
 * Parse an alert timestamp, or return null when it is not an unambiguous
 * ISO 8601 date-time. Requiring an explicit offset means a timestamp without
 * one is never silently read as local time, and checking the calendar fields
 * means 2026-02-31 is rejected instead of rolling over into March.
 */
export function parseAlertTimestamp(raw: string): Date | null {
  const match = ZONED_ISO_TIMESTAMP.exec(raw);
  if (match === null) {
    return null;
  }
  const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
  if (
    year === undefined ||
    month === undefined ||
    day === undefined ||
    hour === undefined ||
    minute === undefined ||
    second === undefined ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > daysInMonth(year, month) ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    return null;
  }
  const date = new Date(raw);
  return Number.isNaN(date.getTime()) ? null : date;
}

function twoDigits(value: number): string {
  return String(value).padStart(2, '0');
}

/**
 * "2026-08-19T18:00:22.557428Z" -> "2026-08-19 18:00:22 UTC".
 *
 * Always UTC, so the same alert reads the same everywhere. A value that is not
 * an unambiguous ISO 8601 date-time is returned unchanged rather than guessed.
 */
export function formatAlertTimestamp(raw: string): string {
  const date = parseAlertTimestamp(raw);
  if (date === null) {
    return raw;
  }
  const day = `${date.getUTCFullYear()}-${twoDigits(date.getUTCMonth() + 1)}-${twoDigits(date.getUTCDate())}`;
  const time = `${twoDigits(date.getUTCHours())}:${twoDigits(date.getUTCMinutes())}:${twoDigits(date.getUTCSeconds())}`;
  return `${day} ${time} UTC`;
}

/** Fill "{name}" placeholders: formatTemplate("{n} alerts", { n: 3 }) -> "3 alerts". */
export function formatTemplate(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (placeholder, name: string) => {
    const value = values[name];
    return value === undefined ? placeholder : String(value);
  });
}
