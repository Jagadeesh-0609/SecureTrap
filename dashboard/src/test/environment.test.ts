import { HttpResponse, delay, http } from 'msw';
import { describe, expect, it, vi } from 'vitest';

import { ApiError, requestJson } from '../api/client';
import { HEALTH_URL, server } from './server';

/**
 * Guards the test environment itself (see jsdom-node-abort-environment.ts).
 *
 * Without it, every request carrying an AbortSignal failed before reaching
 * MSW on newer Node versions, and the API client reported that as a generic
 * "network" error, so the symptom was dozens of misleading failures.
 */
describe('test environment: fetch, AbortSignal and MSW', () => {
  it('still provides the jsdom DOM', () => {
    expect(document.createElement('div')).toBeInstanceOf(HTMLElement);
    expect(window).toBe(globalThis);
  });

  it('creates AbortSignals that fetch accepts', () => {
    const controller = new AbortController();

    expect(controller.signal).toBeInstanceOf(AbortSignal);
    // Throws "Expected signal ... to be an instance of AbortSignal" if the
    // global AbortSignal is not the class the fetch implementation uses.
    expect(new Request('http://api.test/x', { signal: controller.signal }).signal.aborted).toBe(false);
  });

  it('lets MSW answer a request that carries an AbortSignal', async () => {
    const response = await fetch(HEALTH_URL, { signal: new AbortController().signal });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ status: 'ok' });
  });

  it('really cancels an in-flight fetch when its signal is aborted', async () => {
    let handlerStarted = false;
    let handlerSawAbort = false;
    server.use(
      http.get(HEALTH_URL, async ({ request }) => {
        handlerStarted = true;
        request.signal.addEventListener('abort', () => {
          handlerSawAbort = true;
        });
        await delay(2_000);
        return HttpResponse.json({ status: 'ok' });
      }),
    );
    const controller = new AbortController();

    const pending = fetch(HEALTH_URL, { signal: controller.signal });
    // Abort only once the request is genuinely in flight, so the abort has
    // to cancel it rather than prevent it from starting.
    await expect.poll(() => handlerStarted).toBe(true);
    controller.abort();

    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    await expect.poll(() => handlerSawAbort).toBe(true);
  });

  it('surfaces a caller cancellation of requestJson as an AbortError, not an ApiError', async () => {
    server.use(
      http.get(HEALTH_URL, async () => {
        await delay(2_000);
        return HttpResponse.json({ status: 'ok' });
      }),
    );
    const controller = new AbortController();

    const pending = requestJson('/health', { signal: controller.signal });
    controller.abort();
    const error = await pending.then(
      () => undefined,
      (e: unknown) => e,
    );

    expect(error).not.toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ name: 'AbortError' });
  });

  it('cancels the underlying request when requestJson times out', async () => {
    let handlerSawAbort = false;
    server.use(
      http.get(HEALTH_URL, async ({ request }) => {
        request.signal.addEventListener('abort', () => {
          handlerSawAbort = true;
        });
        await delay(2_000);
        return HttpResponse.json({ status: 'ok' });
      }),
    );

    const error = await requestJson('/health', { timeoutMs: 40 }).then(
      () => undefined,
      (e: unknown) => e,
    );

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).kind).toBe('timeout');
    await expect.poll(() => handlerSawAbort).toBe(true);
  });

  it('still refuses requests that no handler answers, instead of reaching a network', async () => {
    // MSW reports the blocked request with console.error; keep that out of the test output.
    const log = vi.spyOn(console, 'error').mockImplementation(() => undefined);

    const error = await fetch('http://unhandled.test/anything').then(
      () => undefined,
      (e: unknown) => e,
    );

    expect(error).toBeInstanceOf(Error);
    expect(log).toHaveBeenCalledWith(expect.stringContaining('without a matching request handler'));
  });
});
