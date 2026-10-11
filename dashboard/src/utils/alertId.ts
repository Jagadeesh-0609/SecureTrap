/**
 * Read an alert ID from a URL segment.
 *
 * Only plain positive whole numbers are accepted ("12", not "0", "-3", "1.5",
 * "1e3", " 7", "abc" or anything that would not survive being an integer). The
 * ID goes into an API request path, so anything else must never get that far.
 */
export function parseAlertIdParam(raw: string | undefined): number | null {
  if (raw === undefined || !/^[1-9]\d{0,15}$/.test(raw)) {
    return null;
  }
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : null;
}
