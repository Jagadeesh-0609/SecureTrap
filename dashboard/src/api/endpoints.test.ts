import { HttpResponse, http } from 'msw';
import { describe, expect, it } from 'vitest';

import { makeAlert, makeAlerts, makeSummary } from '../test/fixtures';
import { ALERTS_URL, HEALTH_URL, SUMMARY_URL, alertUrl, server } from '../test/server';
import { ApiError } from './client';
import { ALERT_LIST_LIMIT, getAlert, getAlerts, getAlertSummary, getHealth } from './endpoints';

describe('getHealth', () => {
  it('requests /health and returns the parsed status', async () => {
    server.use(http.get(HEALTH_URL, () => HttpResponse.json({ status: 'ok' })));

    await expect(getHealth()).resolves.toEqual({ status: 'ok' });
  });

  it('rejects a body that is not a health response', async () => {
    server.use(http.get(HEALTH_URL, () => HttpResponse.json({ nope: true })));

    await expect(getHealth()).rejects.toMatchObject({ kind: 'invalid' });
  });
});

describe('getAlertSummary', () => {
  it('requests /api/v1/alerts/summary and returns the parsed summary', async () => {
    const summary = makeSummary({ total_alerts: 9, anomaly_count: 9, normal_count: 0, anomaly_rate: 1 });
    server.use(http.get(SUMMARY_URL, () => HttpResponse.json(summary)));

    await expect(getAlertSummary()).resolves.toEqual(summary);
  });

  it('rejects a summary that breaks the contract', async () => {
    server.use(http.get(SUMMARY_URL, () => HttpResponse.json({ ...makeSummary(), anomaly_rate: 7 })));

    const error = await getAlertSummary().catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).kind).toBe('invalid');
  });

  it('passes HTTP failures through as http errors', async () => {
    server.use(http.get(SUMMARY_URL, () => HttpResponse.json({ detail: 'x' }, { status: 500 })));

    await expect(getAlertSummary()).rejects.toMatchObject({ kind: 'http', status: 500 });
  });
});

describe('getAlerts', () => {
  it('requests /api/v1/alerts with the default limit and returns the parsed list', async () => {
    const urls: URL[] = [];
    server.use(
      http.get(ALERTS_URL, ({ request }) => {
        urls.push(new URL(request.url));
        return HttpResponse.json(makeAlerts());
      }),
    );

    await expect(getAlerts()).resolves.toEqual(makeAlerts());

    expect(urls).toHaveLength(1);
    expect(urls[0]?.pathname).toBe('/api/v1/alerts');
    expect(urls[0]?.search).toBe(`?limit=${ALERT_LIST_LIMIT}`);
  });

  it('sends a custom limit', async () => {
    let search = '';
    server.use(
      http.get(ALERTS_URL, ({ request }) => {
        search = new URL(request.url).search;
        return HttpResponse.json([]);
      }),
    );

    await expect(getAlerts({ limit: 25 })).resolves.toEqual([]);

    expect(search).toBe('?limit=25');
  });

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53])(
    'refuses the limit %s without making a request',
    async (limit) => {
      let calls = 0;
      server.use(
        http.get(ALERTS_URL, () => {
          calls += 1;
          return HttpResponse.json([]);
        }),
      );

      await expect(getAlerts({ limit })).rejects.toBeInstanceOf(RangeError);

      expect(calls).toBe(0);
    },
  );

  it('rejects a body that is not a list of alerts', async () => {
    server.use(http.get(ALERTS_URL, () => HttpResponse.json({ alerts: [] })));

    await expect(getAlerts()).rejects.toMatchObject({ kind: 'invalid' });
  });

  it('rejects a list containing a malformed alert', async () => {
    server.use(http.get(ALERTS_URL, () => HttpResponse.json([{ ...makeAlert(), score: 'high' }])));

    await expect(getAlerts()).rejects.toMatchObject({ kind: 'invalid' });
  });

  it('passes HTTP failures through as http errors', async () => {
    server.use(http.get(ALERTS_URL, () => HttpResponse.json({ detail: 'x' }, { status: 500 })));

    await expect(getAlerts()).rejects.toMatchObject({ kind: 'http', status: 500 });
  });

  it('reports an unreachable API as a network error', async () => {
    server.use(http.get(ALERTS_URL, () => HttpResponse.error()));

    await expect(getAlerts()).rejects.toMatchObject({ kind: 'network' });
  });
});

describe('getAlert', () => {
  it('requests /api/v1/alerts/{id} and returns the parsed alert', async () => {
    const alert = makeAlert({ id: 42, command: 'id' });
    let path = '';
    server.use(
      http.get(alertUrl(42), ({ request }) => {
        path = new URL(request.url).pathname;
        return HttpResponse.json(alert);
      }),
    );

    await expect(getAlert(42)).resolves.toEqual(alert);

    expect(path).toBe('/api/v1/alerts/42');
  });

  it('reports an unknown ID as an http error with status 404', async () => {
    server.use(http.get(alertUrl(99), () => HttpResponse.json({ detail: 'Alert not found.' }, { status: 404 })));

    await expect(getAlert(99)).rejects.toMatchObject({ kind: 'http', status: 404 });
  });

  it('rejects a body that is not an alert', async () => {
    server.use(http.get(alertUrl(3), () => HttpResponse.json([makeAlert({ id: 3 })])));

    await expect(getAlert(3)).rejects.toMatchObject({ kind: 'invalid' });
  });

  it('passes other HTTP failures through', async () => {
    server.use(http.get(alertUrl(3), () => HttpResponse.json({}, { status: 503 })));

    await expect(getAlert(3)).rejects.toMatchObject({ kind: 'http', status: 503 });
  });

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53, '1/../summary', '7?x=1'])(
    'refuses the ID %s without making a request',
    async (id) => {
      let calls = 0;
      server.use(
        http.get(`${ALERTS_URL}/*`, () => {
          calls += 1;
          return HttpResponse.json(makeAlert());
        }),
      );

      await expect(getAlert(id as number)).rejects.toBeInstanceOf(RangeError);

      expect(calls).toBe(0);
    },
  );
});
