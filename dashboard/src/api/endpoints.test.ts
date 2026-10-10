import { HttpResponse, http } from 'msw';
import { describe, expect, it } from 'vitest';

import { makeSummary } from '../test/fixtures';
import { HEALTH_URL, SUMMARY_URL, server } from '../test/server';
import { ApiError } from './client';
import { getAlertSummary, getHealth } from './endpoints';

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
