import type { Environment } from 'vitest/environments';
import { builtinEnvironments } from 'vitest/environments';

/**
 * Vitest's built-in jsdom environment, except that `AbortController` and
 * `AbortSignal` stay Node's own.
 *
 * Why this exists: jsdom ships its own AbortController / AbortSignal, and
 * Vitest's jsdom environment installs them as globals, replacing Node's.
 * Node's fetch (undici) only accepts a signal that is an instance of Node's
 * own AbortSignal, and rejects jsdom's with
 *   TypeError: RequestInit: Expected signal ("AbortSignal {}") to be an
 *   instance of AbortSignal.
 * Node 24 enforces this when a Request is built (which MSW does for every
 * intercepted fetch); Node 22 accepted either kind. Every request made by the
 * dashboard's API client carries a signal (for its timeout), so on Node 24
 * every request in the test suite failed before reaching MSW.
 *
 * Keeping Node's classes means signals are real, cancellable ones that fetch
 * and MSW accept: aborting still cancels the in-flight request. Everything
 * else about the jsdom environment (document, window, DOM events, ...) is
 * untouched.
 *
 * The Node classes are captured when this module is first evaluated, which is
 * before the jsdom environment replaces the globals.
 */
const NodeAbortController = globalThis.AbortController;
const NodeAbortSignal = globalThis.AbortSignal;

const jsdomEnvironment = builtinEnvironments.jsdom;

const environment: Environment = {
  name: 'jsdom-with-node-abort',
  transformMode: jsdomEnvironment.transformMode,
  async setup(global, options) {
    const result = await jsdomEnvironment.setup(global, options);

    // Same attributes as Node's own globals: writable, not enumerable.
    Object.defineProperties(global, {
      AbortController: { value: NodeAbortController, writable: true, configurable: true },
      AbortSignal: { value: NodeAbortSignal, writable: true, configurable: true },
    });

    // Fail loudly, with the reason, if a future Node or Vitest breaks the
    // assumption above, instead of surfacing as dozens of unrelated
    // "network error" test failures. Building a Request is what fetch does
    // first; it touches no network.
    try {
      new Request('http://localhost/', { signal: new global.AbortController().signal });
    } catch (cause) {
      throw new Error(
        'Test environment: fetch rejects the global AbortSignal, so every request carrying a ' +
          'signal would fail. See src/test/jsdom-node-abort-environment.ts.',
        { cause },
      );
    }

    return result;
  },
};

export default environment;
