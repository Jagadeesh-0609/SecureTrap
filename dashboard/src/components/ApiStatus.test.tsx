import { screen } from '@testing-library/react';
import { HttpResponse, http } from 'msw';
import { describe, expect, it } from 'vitest';

import { deferred, renderWithQuery } from '../test/render';
import { HEALTH_URL, server } from '../test/server';
import { ApiStatus } from './ApiStatus';

describe('ApiStatus', () => {
  it('shows a checking state while /health is in flight', async () => {
    const gate = deferred();
    server.use(
      http.get(HEALTH_URL, async () => {
        await gate.promise;
        return HttpResponse.json({ status: 'ok' });
      }),
    );

    renderWithQuery(<ApiStatus />);

    expect(screen.getByRole('status')).toHaveAttribute('data-state', 'checking');
    expect(screen.getByText('Checking API…')).toBeInTheDocument();
    gate.resolve();
    expect(await screen.findByText('API reachable')).toBeInTheDocument();
  });

  it('says only that the API is reachable when /health returns ok', async () => {
    renderWithQuery(<ApiStatus />);

    expect(await screen.findByText('API reachable')).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveAttribute('data-state', 'reachable');
  });

  it('states that a reachable API does not prove the detection system works', async () => {
    renderWithQuery(<ApiStatus />);

    await screen.findByText('API reachable');

    const text = screen.getByRole('status').textContent ?? '';
    expect(text).toMatch(/does not verify the database, the detection service, or the honeypot/i);
    expect(text).not.toMatch(/healthy|operational|all systems|running normally/i);
  });

  it('shows API unreachable when the request fails', async () => {
    server.use(http.get(HEALTH_URL, () => HttpResponse.error()));

    renderWithQuery(<ApiStatus />);

    expect(await screen.findByText('API unreachable')).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveAttribute('data-state', 'unreachable');
  });

  it('shows the HTTP status when /health answers with an error', async () => {
    server.use(http.get(HEALTH_URL, () => HttpResponse.json({ detail: 'x' }, { status: 503 })));

    renderWithQuery(<ApiStatus />);

    expect(await screen.findByText('API error (HTTP 503)')).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveAttribute('data-state', 'error');
    // The request did complete here, so the description must not claim otherwise.
    expect(screen.getByRole('status').textContent).not.toMatch(/did not complete/i);
  });

  it('flags a /health body that is not in the expected format', async () => {
    server.use(http.get(HEALTH_URL, () => HttpResponse.json({ unexpected: true })));

    renderWithQuery(<ApiStatus />);

    expect(await screen.findByText('API responded')).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveAttribute('data-state', 'unexpected');
  });

  it('does not report reachable for a status other than "ok"', async () => {
    server.use(http.get(HEALTH_URL, () => HttpResponse.json({ status: 'degraded' })));

    renderWithQuery(<ApiStatus />);

    expect(await screen.findByText('API responded: degraded')).toBeInTheDocument();
    expect(screen.queryByText('API reachable')).not.toBeInTheDocument();
  });

  it('renders a hostile status string as inert text, never as HTML', async () => {
    const hostile = '<img src=x onerror="alert(1)">';
    server.use(http.get(HEALTH_URL, () => HttpResponse.json({ status: hostile })));

    const { container } = renderWithQuery(<ApiStatus />);

    expect(await screen.findByText(`API responded: ${hostile}`)).toBeInTheDocument();
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('[onerror]')).toBeNull();
  });

  it('shortens a very long status string so it cannot break the layout', async () => {
    server.use(http.get(HEALTH_URL, () => HttpResponse.json({ status: 'x'.repeat(500) })));

    renderWithQuery(<ApiStatus />);

    const label = await screen.findByText(/^API responded: x+…$/);
    expect(label.textContent?.length).toBeLessThan(80);
  });
});
