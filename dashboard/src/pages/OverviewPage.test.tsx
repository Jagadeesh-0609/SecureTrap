import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { HttpResponse, http } from 'msw';
import { describe, expect, it } from 'vitest';

import { makeAllFlaggedSummary, makeEmptySummary, makeSummary } from '../test/fixtures';
import { deferred, renderApp } from '../test/render';
import { HEALTH_URL, SUMMARY_URL, server } from '../test/server';

function card(name: string) {
  return screen.findByRole('article', { name });
}

describe('OverviewPage: loaded states', () => {
  it('shows the four summary cards from GET /api/v1/alerts/summary', async () => {
    renderApp();

    expect(within(await card('Persisted alerts')).getByText('5')).toBeInTheDocument();
    expect(within(await card('Persisted anomalies')).getByText('2')).toBeInTheDocument();
    expect(within(await card('Persisted non-anomalous records')).getByText('3')).toBeInTheDocument();
    expect(within(await card('Anomaly share of persisted records')).getByText('40%')).toBeInTheDocument();
    expect(screen.getAllByRole('article')).toHaveLength(4);
  });

  it('shows when the data was last updated', async () => {
    renderApp();

    await card('Persisted alerts');

    expect(screen.getByText(/^Updated/)).toHaveTextContent(/Updated \d{2}:\d{2}:\d{2}/);
  });

  it('explains a 100% share when the store holds only flagged records', async () => {
    server.use(http.get(SUMMARY_URL, () => HttpResponse.json(makeAllFlaggedSummary(7))));

    renderApp();

    expect(within(await card('Persisted alerts')).getByText('7')).toBeInTheDocument();
    expect(within(await card('Persisted non-anomalous records')).getByText('0')).toBeInTheDocument();
    expect(within(await card('Anomaly share of persisted records')).getByText('100%')).toBeInTheDocument();
    expect(screen.getByRole('note')).toHaveTextContent(/every stored record is flagged/i);
  });

  it('always states that the figures describe persisted records only', async () => {
    renderApp();

    await card('Persisted alerts');

    const banner = screen.getByRole('complementary', { name: 'What these figures describe' });
    expect(banner).toHaveTextContent(/persisted in the SecureTrap alert store/i);
    expect(banner).toHaveTextContent(/not a count of every prediction the model has made/i);
    expect(banner).toHaveTextContent(/not a confirmed attack/i);
    expect(banner).toHaveTextContent(/not probabilities or confidence values/i);
  });
});

describe('OverviewPage: loading state', () => {
  it('shows a loading placeholder, with the scope banner, until the summary arrives', async () => {
    const gate = deferred();
    server.use(
      http.get(SUMMARY_URL, async () => {
        await gate.promise;
        return HttpResponse.json(makeSummary());
      }),
    );

    renderApp();

    expect(screen.getByText('Loading alert summary…')).toBeInTheDocument();
    expect(screen.queryByRole('article')).not.toBeInTheDocument();
    expect(screen.getByRole('complementary', { name: 'What these figures describe' })).toBeInTheDocument();

    gate.resolve();
    expect(await card('Persisted alerts')).toBeInTheDocument();
    expect(screen.queryByText('Loading alert summary…')).not.toBeInTheDocument();
  });
});

describe('OverviewPage: empty state', () => {
  it('shows an empty state instead of zero-valued cards when nothing is persisted', async () => {
    server.use(http.get(SUMMARY_URL, () => HttpResponse.json(makeEmptySummary())));

    renderApp();

    expect(await screen.findByRole('heading', { name: 'No alerts persisted yet' })).toBeInTheDocument();
    expect(screen.queryByRole('article')).not.toBeInTheDocument();
  });

  it('does not claim an empty store means nothing is happening', async () => {
    server.use(http.get(SUMMARY_URL, () => HttpResponse.json(makeEmptySummary())));

    renderApp();

    await screen.findByRole('heading', { name: 'No alerts persisted yet' });
    expect(screen.getByText(/cannot tell "nothing has been flagged" apart from/i)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/all clear|no threats|nothing to worry|healthy|operational/i);
  });
});

describe('OverviewPage: API unavailable', () => {
  it('shows the unavailable state when the request cannot complete', async () => {
    server.use(http.get(SUMMARY_URL, () => HttpResponse.error()));

    renderApp();

    const alert = await screen.findByRole('alert');
    expect(within(alert).getByRole('heading', { name: 'Cannot reach the SecureTrap API' })).toBeInTheDocument();
    expect(screen.queryByRole('article')).not.toBeInTheDocument();
  });

  it('offers the likely causes, including CORS, and shows where requests go', async () => {
    server.use(http.get(SUMMARY_URL, () => HttpResponse.error()));

    renderApp();

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/SECURETRAP_CORS_ORIGINS/);
    expect(alert).toHaveTextContent(/VITE_API_BASE_URL/);
    expect(within(alert).getByText('http://api.test')).toBeInTheDocument();
  });

  it('keeps the scope banner visible while the API is unavailable', async () => {
    server.use(http.get(SUMMARY_URL, () => HttpResponse.error()));

    renderApp();

    await screen.findByRole('alert');
    expect(screen.getByRole('complementary', { name: 'What these figures describe' })).toBeInTheDocument();
  });

  it('recovers when the API comes back and the user tries again', async () => {
    server.use(http.get(SUMMARY_URL, () => HttpResponse.error()));
    const user = userEvent.setup();
    renderApp();
    await screen.findByRole('heading', { name: 'Cannot reach the SecureTrap API' });

    server.use(http.get(SUMMARY_URL, () => HttpResponse.json(makeSummary())));
    await user.click(screen.getByRole('button', { name: 'Try again' }));

    expect(within(await card('Persisted alerts')).getByText('5')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Cannot reach the SecureTrap API' })).not.toBeInTheDocument();
  });

  it('treats a timeout the same way as an unreachable API', async () => {
    // A zero-length timeout is not configurable here, so simulate the
    // ApiError a timeout produces by failing the connection; the kind-level
    // mapping for "timeout" is covered in overviewState.test.ts.
    server.use(http.get(SUMMARY_URL, () => HttpResponse.error()));

    renderApp();

    expect(await screen.findByRole('heading', { name: 'Cannot reach the SecureTrap API' })).toBeInTheDocument();
  });
});

describe('OverviewPage: error states', () => {
  it('shows an error state, with the status code, when the API answers HTTP 500', async () => {
    server.use(http.get(SUMMARY_URL, () => HttpResponse.json({ detail: 'Internal server error.' }, { status: 500 })));

    renderApp();

    const alert = await screen.findByRole('alert');
    expect(within(alert).getByRole('heading', { name: 'The API returned an error' })).toBeInTheDocument();
    expect(alert).toHaveTextContent('HTTP 500');
    expect(screen.queryByRole('article')).not.toBeInTheDocument();
  });

  it('shows an unexpected-response state when the body breaks the contract', async () => {
    server.use(http.get(SUMMARY_URL, () => HttpResponse.json({ ...makeSummary(), anomaly_rate: 5 })));

    renderApp();

    const alert = await screen.findByRole('alert');
    expect(within(alert).getByRole('heading', { name: 'Unexpected API response' })).toBeInTheDocument();
    expect(alert).toHaveTextContent('anomaly_rate');
    expect(screen.queryByRole('article')).not.toBeInTheDocument();
  });

  it('shows the unexpected-response state when the body is not JSON', async () => {
    server.use(
      http.get(
        SUMMARY_URL,
        () => new HttpResponse('<html>gateway</html>', { status: 200, headers: { 'Content-Type': 'text/html' } }),
      ),
    );

    renderApp();

    expect(await screen.findByRole('heading', { name: 'Unexpected API response' })).toBeInTheDocument();
  });

  it('never renders server-provided error text', async () => {
    server.use(
      http.get(SUMMARY_URL, () => HttpResponse.json({ detail: '<img src=x onerror=alert(1)>' }, { status: 500 })),
    );

    const { container } = renderApp();

    await screen.findByRole('heading', { name: 'The API returned an error' });
    expect(document.body.textContent).not.toContain('onerror');
    expect(container.querySelector('img')).toBeNull();
  });

  it('lets the user retry after an error', async () => {
    server.use(http.get(SUMMARY_URL, () => HttpResponse.json({}, { status: 500 })));
    const user = userEvent.setup();
    renderApp();
    await screen.findByRole('heading', { name: 'The API returned an error' });

    server.use(http.get(SUMMARY_URL, () => HttpResponse.json(makeSummary())));
    await user.click(screen.getByRole('button', { name: 'Try again' }));

    expect(await card('Persisted alerts')).toBeInTheDocument();
  });
});

describe('OverviewPage: refresh', () => {
  it('refetches the summary when Refresh is pressed', async () => {
    let calls = 0;
    server.use(
      http.get(SUMMARY_URL, () => {
        calls += 1;
        return HttpResponse.json(makeSummary({ total_alerts: 5 + calls }));
      }),
    );
    const user = userEvent.setup();
    renderApp();
    expect(within(await card('Persisted alerts')).getByText('6')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Refresh' }));

    await waitFor(() => expect(within(screen.getByRole('article', { name: 'Persisted alerts' })).getByText('7')).toBeInTheDocument());
    expect(calls).toBe(2);
  });

  it('keeps the last data visible, marked stale, when a refresh fails', async () => {
    const user = userEvent.setup();
    renderApp();
    expect(within(await card('Persisted alerts')).getByText('5')).toBeInTheDocument();

    server.use(http.get(SUMMARY_URL, () => HttpResponse.error()));
    await user.click(screen.getByRole('button', { name: 'Refresh' }));

    const notice = await screen.findByText(/Showing the last data received at/i);
    expect(notice).toHaveTextContent(/The latest refresh failed:/);
    expect(notice).toHaveTextContent(/could not be reached/i);
    expect(within(screen.getByRole('article', { name: 'Persisted alerts' })).getByText('5')).toBeInTheDocument();
  });

  it('clears the stale notice once a later refresh succeeds', async () => {
    const user = userEvent.setup();
    renderApp();
    await card('Persisted alerts');
    server.use(http.get(SUMMARY_URL, () => HttpResponse.error()));
    await user.click(screen.getByRole('button', { name: 'Refresh' }));
    await screen.findByText(/Showing the last data received at/i);

    server.use(http.get(SUMMARY_URL, () => HttpResponse.json(makeSummary({ total_alerts: 9, anomaly_count: 4, normal_count: 5, anomaly_rate: 4 / 9 }))));
    await user.click(screen.getByRole('button', { name: 'Refresh' }));

    await waitFor(() => expect(screen.queryByText(/Showing the last data received at/i)).not.toBeInTheDocument());
    expect(within(screen.getByRole('article', { name: 'Persisted alerts' })).getByText('9')).toBeInTheDocument();
  });
});

describe('OverviewPage: health versus detection', () => {
  it('shows only "API reachable" when /health succeeds, never a system-health claim', async () => {
    renderApp();

    await card('Persisted alerts');

    expect(await screen.findByText('API reachable')).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/healthy|operational|all systems|detection (is )?(running|active|working)/i);
  });

  it('keeps showing summary data when only /health is failing', async () => {
    server.use(http.get(HEALTH_URL, () => HttpResponse.error()));

    renderApp();

    expect(within(await card('Persisted alerts')).getByText('5')).toBeInTheDocument();
    expect(await screen.findByText('API unreachable')).toBeInTheDocument();
  });

  it('shows the unavailable state without a green indicator when everything fails', async () => {
    server.use(http.get(HEALTH_URL, () => HttpResponse.error()), http.get(SUMMARY_URL, () => HttpResponse.error()));

    renderApp();

    await screen.findByRole('heading', { name: 'Cannot reach the SecureTrap API' });
    expect(await screen.findByText('API unreachable')).toBeInTheDocument();
    expect(screen.queryByText('API reachable')).not.toBeInTheDocument();
  });
});
