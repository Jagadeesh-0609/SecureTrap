/** How long a single API request may take before the API is treated as unreachable. */
export const REQUEST_TIMEOUT_MS = 10_000;

/** How often the overview refreshes itself while the browser tab is visible. */
export const REFRESH_INTERVAL_MS = 30_000;

export type ApiConfig = { ok: true; baseUrl: string } | { ok: false; reason: string };

function invalid(reason: string): ApiConfig {
  return { ok: false, reason };
}

function stripTrailingSlashes(value: string): string {
  return value.replace(/\/+$/, '');
}

/**
 * Validate and normalise the configured API base URL (VITE_API_BASE_URL).
 *
 * Accepted forms:
 *   - empty / unset            -> same-origin requests (base URL "")
 *   - an absolute http(s) URL  -> e.g. http://localhost:8000
 *   - a path such as /api-prefix -> same-origin, prefixed
 *
 * Anything else is rejected so a typo (for example "localhost:8000", which a
 * browser would treat as a relative path) fails loudly instead of silently
 * sending requests to the wrong place. A "/path" prefix is guaranteed to stay
 * same-origin: values containing backslashes, and protocol-relative "//host"
 * values, are rejected. The offending value is never echoed.
 */
export function resolveApiBaseUrl(raw: string | undefined): ApiConfig {
  const value = (raw ?? '').trim();

  if (value === '') {
    return { ok: true, baseUrl: '' };
  }
  if (/[\s?#]/.test(value)) {
    return invalid('must not contain whitespace, a query string or a fragment.');
  }
  // Browsers (WHATWG URL parsing) treat "\" as "/" in http(s) URLs, so "/\host"
  // would resolve to another origin even though it looks like a same-origin
  // path, and "http:\\host" or "http://a\@b" would parse differently from how
  // they read. Reject every backslash before any path or URL form is accepted.
  if (value.includes('\\')) {
    return invalid('must not contain backslashes.');
  }
  if (value.startsWith('//')) {
    return invalid('must not be a protocol-relative URL; use an absolute http(s) URL or a /path.');
  }
  if (value.startsWith('/')) {
    return { ok: true, baseUrl: stripTrailingSlashes(value) };
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return invalid('is not a valid URL. Use an absolute http(s) URL such as http://localhost:8000.');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return invalid('must use http or https.');
  }
  if (url.username !== '' || url.password !== '') {
    return invalid('must not contain credentials.');
  }
  return { ok: true, baseUrl: stripTrailingSlashes(`${url.origin}${url.pathname}`) };
}

/** The API configuration resolved once from the build-time environment. */
export const apiConfig: ApiConfig = resolveApiBaseUrl(import.meta.env.VITE_API_BASE_URL);

/** Human-readable description of where API requests are sent. */
export function describeApiBase(baseUrl: string): string {
  return baseUrl === '' ? 'the same origin as this dashboard' : baseUrl;
}
