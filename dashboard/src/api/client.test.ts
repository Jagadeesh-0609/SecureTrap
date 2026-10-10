import { HttpResponse, delay, http } from 'msw';
import { describe, expect, it } from 'vitest';

import { HEALTH_URL, server } from '../test/server';
import { ApiError, requestJson } from './client';

async function caught(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('Expected the request to fail.');
}

describe('requestJson', () => {
  it('returns the parsed JSON body of a successful response', async () => {
    server.use(http.get(HEALTH_URL, () => HttpResponse.json({ status: 'ok' })));

    await expect(requestJson('/health')).resolves.toEqual({ status: 'ok' });
  });

  it('sends a plain GET asking for JSON, with no cookies or credentials headers', async () => {
    let seen: Request | undefined;
    server.use(
      http.get(HEALTH_URL, ({ request }) => {
        seen = request;
        return HttpResponse.json({ status: 'ok' });
      }),
    );

    await requestJson('/health');

    expect(seen?.method).toBe('GET');
    expect(seen?.headers.get('accept')).toContain('application/json');
    expect(seen?.headers.get('authorization')).toBeNull();
    expect(seen?.headers.get('cookie')).toBeNull();
  });

  it('uses an explicitly supplied base URL instead of the configured one', async () => {
    server.use(http.get('http://other.test/health', () => HttpResponse.json({ status: 'other' })));

    await expect(requestJson('/health', { baseUrl: 'http://other.test' })).resolves.toEqual({
      status: 'other',
    });
  });

  it.each([404, 500, 503])('reports HTTP %i as an http error carrying the status', async (status) => {
    server.use(http.get(HEALTH_URL, () => HttpResponse.json({ detail: 'x' }, { status })));

    const error = await caught(requestJson('/health'));

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).kind).toBe('http');
    expect((error as ApiError).status).toBe(status);
    expect((error as ApiError).message).toContain(`HTTP ${status}`);
  });

  it('does not put the server-provided error detail into the error message', async () => {
    server.use(
      http.get(HEALTH_URL, () => HttpResponse.json({ detail: '<script>alert(1)</script>' }, { status: 500 })),
    );

    const error = await caught(requestJson('/health'));

    expect((error as ApiError).message).not.toContain('script');
  });

  it('reports a failed connection as a network error', async () => {
    server.use(http.get(HEALTH_URL, () => HttpResponse.error()));

    const error = await caught(requestJson('/health'));

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).kind).toBe('network');
  });

  it('reports a slow API as a timeout', async () => {
    server.use(
      http.get(HEALTH_URL, async () => {
        await delay(400);
        return HttpResponse.json({ status: 'ok' });
      }),
    );

    const error = await caught(requestJson('/health', { timeoutMs: 40 }));

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).kind).toBe('timeout');
  });

  it('reports a 2xx response that is not JSON as an invalid response', async () => {
    server.use(
      http.get(
        HEALTH_URL,
        () =>
          new HttpResponse('<html>proxy error page</html>', {
            status: 200,
            headers: { 'Content-Type': 'text/html' },
          }),
      ),
    );

    const error = await caught(requestJson('/health'));

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).kind).toBe('invalid');
  });

  it('lets a caller-initiated cancellation through without calling it an API failure', async () => {
    server.use(
      http.get(HEALTH_URL, async () => {
        await delay(400);
        return HttpResponse.json({ status: 'ok' });
      }),
    );
    const controller = new AbortController();

    const pending = caught(requestJson('/health', { signal: controller.signal }));
    controller.abort();
    const error = await pending;

    expect(error).not.toBeInstanceOf(ApiError);
  });
});
