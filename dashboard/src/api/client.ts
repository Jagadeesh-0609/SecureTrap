import { REQUEST_TIMEOUT_MS, apiConfig } from '../config';

/**
 * network: the request never completed (API down, DNS, or a CORS block -
 *          browsers report these identically).
 * timeout: the request took longer than the allowed time.
 * http:    the API answered with a non-2xx status.
 * invalid: the API answered 2xx but not with the expected JSON.
 */
export type ApiErrorKind = 'network' | 'timeout' | 'http' | 'invalid';

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number | undefined;

  constructor(kind: ApiErrorKind, message: string, status?: number) {
    super(message);
    this.name = 'ApiError';
    this.kind = kind;
    this.status = status;
  }
}

export interface RequestOptions {
  /** Overrides the configured API base URL (used by tests). */
  baseUrl?: string;
  timeoutMs?: number;
  /** Lets the caller (React Query) cancel the request. */
  signal?: AbortSignal;
}

function configuredBaseUrl(): string {
  if (!apiConfig.ok) {
    // The app shows a configuration error page instead of mounting any
    // component that could reach this line.
    throw new Error('The API base URL is not configured correctly.');
  }
  return apiConfig.baseUrl;
}

/**
 * GET a JSON document from the SecureTrap API.
 *
 * `path` must be a constant owned by this code base (for example
 * "/health"), never a value derived from API data. Requests are
 * credential-less: the dashboard needs no cookies.
 */
export async function requestJson(path: string, options: RequestOptions = {}): Promise<unknown> {
  const { baseUrl = configuredBaseUrl(), timeoutMs = REQUEST_TIMEOUT_MS, signal } = options;

  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const forwardAbort = () => controller.abort();
  signal?.addEventListener('abort', forwardAbort, { once: true });

  try {
    let response: Response;
    try {
      response = await fetch(`${baseUrl}${path}`, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        credentials: 'omit',
        signal: controller.signal,
      });
    } catch (cause) {
      if (timedOut) {
        throw new ApiError('timeout', 'The API did not respond in time.');
      }
      if (signal?.aborted) {
        throw cause; // cancelled by the caller; not an API failure
      }
      throw new ApiError('network', 'The API could not be reached.');
    }

    if (!response.ok) {
      throw new ApiError('http', `The API responded with HTTP ${response.status}.`, response.status);
    }

    try {
      return await response.json();
    } catch {
      if (timedOut) {
        throw new ApiError('timeout', 'The API did not respond in time.');
      }
      throw new ApiError('invalid', 'The API response was not valid JSON.');
    }
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', forwardAbort);
  }
}
