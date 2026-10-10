import { describe, expect, it } from 'vitest';

import { apiConfig, describeApiBase, resolveApiBaseUrl } from './config';

describe('resolveApiBaseUrl', () => {
  it.each([undefined, '', '   '])('treats %j as same-origin', (raw) => {
    expect(resolveApiBaseUrl(raw)).toEqual({ ok: true, baseUrl: '' });
  });

  it('accepts an absolute http URL unchanged', () => {
    expect(resolveApiBaseUrl('http://localhost:8000')).toEqual({
      ok: true,
      baseUrl: 'http://localhost:8000',
    });
  });

  it('accepts an https URL and keeps its path', () => {
    expect(resolveApiBaseUrl('https://example.org/securetrap')).toEqual({
      ok: true,
      baseUrl: 'https://example.org/securetrap',
    });
  });

  it('strips trailing slashes and surrounding whitespace', () => {
    expect(resolveApiBaseUrl('  http://localhost:8000///  ')).toEqual({
      ok: true,
      baseUrl: 'http://localhost:8000',
    });
    expect(resolveApiBaseUrl('https://example.org/securetrap/')).toEqual({
      ok: true,
      baseUrl: 'https://example.org/securetrap',
    });
  });

  it('accepts a same-origin path prefix', () => {
    expect(resolveApiBaseUrl('/securetrap-api/')).toEqual({ ok: true, baseUrl: '/securetrap-api' });
    expect(resolveApiBaseUrl('/')).toEqual({ ok: true, baseUrl: '' });
  });

  it.each([
    ['a host without a scheme', 'localhost:8000'],
    ['a non-http scheme', 'ftp://example.org'],
    ['a javascript: URL', 'javascript:alert(1)'],
    ['a protocol-relative URL', '//evil.example'],
    ['a URL with credentials', 'http://user:secret@example.org'],
    ['a URL with a query string', 'http://example.org?x=1'],
    ['a URL with a fragment', 'http://example.org/#frag'],
    ['text containing whitespace', 'http://exa mple.org'],
    ['not a URL at all', 'definitely not a url'],
  ])('rejects %s', (_label, raw) => {
    const result = resolveApiBaseUrl(raw);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason.length).toBeGreaterThan(0);
    }
  });

  it('never echoes the rejected value (it may contain credentials)', () => {
    const result = resolveApiBaseUrl('http://user:secret@example.org');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).not.toContain('secret');
      expect(result.reason).not.toContain('example.org');
    }
  });

  describe('backslashes', () => {
    // A browser treats "\" as "/" in http(s) URLs, so "/\evil.example" would
    // resolve to http://evil.example/ instead of staying on the dashboard's
    // origin. Note: in these JS strings, '\\' is ONE backslash character.
    const DASHBOARD_ORIGIN = 'http://dashboard.test';

    it.each([
      ['a path prefix starting with a single backslash after the slash', '/\\evil.example'],
      ['a path prefix with multiple backslashes', '/\\\\evil.example'],
      ['a path prefix with many backslashes', '/\\\\\\\\evil.example'],
      ['a path prefix mixing a backslash and a slash', '/\\/evil.example'],
      ['a path prefix with a backslash after a real segment', '/securetrap-api\\evil.example'],
      ['a path prefix with a trailing backslash', '/securetrap-api\\'],
      ['a leading backslash with no slash', '\\evil.example'],
      ['an http URL using backslashes after the scheme', 'http:\\\\evil.example'],
      ['an https URL with a backslash in the authority', 'https://example.org\\@evil.example'],
      ['an absolute URL with a backslash in its path', 'http://localhost:8000\\api'],
      ['a backslash value surrounded by whitespace that gets trimmed', '  /\\evil.example  '],
    ])('rejects %s', (_label, raw) => {
      const result = resolveApiBaseUrl(raw);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toMatch(/backslash/i);
      }
    });

    it('never echoes a rejected backslash value, or any part of it', () => {
      for (const raw of ['/\\evil.example', '/\\\\evil.example', 'https://example.org\\@evil.example']) {
        const result = resolveApiBaseUrl(raw);
        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.reason).not.toContain('evil');
          expect(result.reason).not.toContain('example');
          expect(result.reason).not.toContain('\\');
        }
      }
    });

    it('still accepts ordinary path prefixes, and each one stays on the dashboard origin', () => {
      for (const [raw, expected] of [
        ['/securetrap-api', '/securetrap-api'],
        ['/securetrap-api/', '/securetrap-api'],
        ['/securetrap-api/v1', '/securetrap-api/v1'],
        ['/', ''],
      ] as const) {
        const result = resolveApiBaseUrl(raw);
        expect(result).toEqual({ ok: true, baseUrl: expected });
        if (result.ok) {
          expect(new URL(`${result.baseUrl}/health`, DASHBOARD_ORIGIN).origin).toBe(DASHBOARD_ORIGIN);
        }
      }
    });

    it('never produces a path prefix that a browser would resolve to another origin', () => {
      const hostile = [
        '/\\evil.example',
        '/\\\\evil.example',
        '/\\/evil.example',
        '//evil.example',
        '/%5Cevil.example',
        '/%2F%2Fevil.example',
      ];
      for (const raw of hostile) {
        const result = resolveApiBaseUrl(raw);
        if (result.ok) {
          // Anything that IS accepted must still be a same-origin path.
          expect(new URL(`${result.baseUrl}/health`, DASHBOARD_ORIGIN).origin).toBe(DASHBOARD_ORIGIN);
        }
      }
      // ...and the two raw forms that are real cross-origin bypasses are rejected outright.
      expect(resolveApiBaseUrl('/\\evil.example').ok).toBe(false);
      expect(resolveApiBaseUrl('//evil.example').ok).toBe(false);
    });

    it('keeps the existing rejections and acceptances intact alongside the new rule', () => {
      expect(resolveApiBaseUrl('http://localhost:8000')).toEqual({ ok: true, baseUrl: 'http://localhost:8000' });
      expect(resolveApiBaseUrl('https://example.org/securetrap')).toEqual({
        ok: true,
        baseUrl: 'https://example.org/securetrap',
      });
      expect(resolveApiBaseUrl('')).toEqual({ ok: true, baseUrl: '' });
      expect(resolveApiBaseUrl(undefined)).toEqual({ ok: true, baseUrl: '' });

      for (const raw of [
        '//evil.example',
        'http://user:secret@example.org',
        'http://example.org?x=1',
        'http://example.org/#frag',
        'localhost:8000',
        'ftp://example.org',
      ]) {
        expect(resolveApiBaseUrl(raw).ok).toBe(false);
      }
    });
  });
});

describe('describeApiBase', () => {
  it('names the same origin when no base URL is set', () => {
    expect(describeApiBase('')).toMatch(/same origin/i);
  });

  it('returns a configured base URL as-is', () => {
    expect(describeApiBase('http://localhost:8000')).toBe('http://localhost:8000');
  });
});

describe('apiConfig in the test environment', () => {
  it('uses the fake API origin from the test configuration, never a real host', () => {
    expect(apiConfig).toEqual({ ok: true, baseUrl: 'http://api.test' });
  });
});
