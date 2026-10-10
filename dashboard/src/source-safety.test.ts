import { describe, expect, it } from 'vitest';

/*
 * Static guards over the dashboard's own (non-test) source files. Honeypot
 * data is untrusted, so the code base must have no way to turn it into HTML
 * or script, must not persist it in the browser, and must not hard-code a
 * remote API address. These checks read the source text so a later change
 * that breaks a rule fails the suite.
 */

const rawSources = import.meta.glob<string>('./**/*.{ts,tsx}', {
  query: '?raw',
  import: 'default',
  eager: true,
});

function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '')
    .replace(/\s\/\/\s.*$/gm, '');
}

const appSources = Object.entries(rawSources)
  .filter(([path]) => !/\.test\.tsx?$/.test(path) && !path.startsWith('./test/'))
  .map(([path, source]) => ({ path, code: stripComments(source) }));

describe('source safety', () => {
  it('scans a realistic number of application files', () => {
    expect(appSources.length).toBeGreaterThan(15);
    expect(appSources.some((file) => file.path === './copy.ts')).toBe(true);
    expect(appSources.some((file) => file.path.endsWith('.test.ts'))).toBe(false);
  });

  it('has no way to inject HTML or run strings as code', () => {
    const forbidden =
      /dangerouslySetInnerHTML\s*=|\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(|document\.write\s*\(|\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['"`]/;
    for (const { path, code } of appSources) {
      expect(code, path).not.toMatch(forbidden);
    }
  });

  it('does not store anything in the browser', () => {
    for (const { path, code } of appSources) {
      expect(code, path).not.toMatch(/\b(?:localStorage|sessionStorage|indexedDB)\b|document\.cookie/);
    }
  });

  it('does not hard-code a remote address', () => {
    for (const { path, code } of appSources) {
      expect(code, path).not.toMatch(/https?:\/\/(?!localhost\b|127\.0\.0\.1\b)[a-z0-9.-]+/i);
    }
  });

  it('keeps semantics-bearing wording in copy.ts only', () => {
    const vocabulary = /\b(?:attacks?|threats?|malicious|confidence|probabilit(?:y|ies)|healthy|operational)\b/i;
    for (const { path, code } of appSources.filter((file) => file.path !== './copy.ts')) {
      expect(code, path).not.toMatch(vocabulary);
    }
  });
});
