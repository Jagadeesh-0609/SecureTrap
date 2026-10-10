const NUMBER_LOCALE = 'en-US';

const countFormatter = new Intl.NumberFormat(NUMBER_LOCALE);
const percentFormatter = new Intl.NumberFormat(NUMBER_LOCALE, {
  style: 'percent',
  maximumFractionDigits: 1,
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
