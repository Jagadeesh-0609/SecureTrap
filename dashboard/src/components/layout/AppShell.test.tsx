import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { ConfigErrorPage } from '../../pages/ConfigErrorPage';
import { renderApp } from '../../test/render';

describe('AppShell', () => {
  it('provides a skip link that targets the main content', async () => {
    renderApp();

    const skip = screen.getByRole('link', { name: 'Skip to main content' });
    expect(skip).toHaveAttribute('href', '#main-content');
    expect(screen.getByRole('main')).toHaveAttribute('id', 'main-content');
    await screen.findByText('API reachable');
  });

  it('shows the product name, a primary navigation and the API status', async () => {
    renderApp();

    const header = screen.getByRole('banner');
    expect(within(header).getByText('SecureTrap')).toBeInTheDocument();
    expect(within(header).getByRole('navigation', { name: 'Primary' })).toBeInTheDocument();
    expect(await within(header).findByText('API reachable')).toBeInTheDocument();
  });

  it('marks the Overview link as the current page', async () => {
    renderApp('/');

    const link = screen.getByRole('link', { name: 'Overview' });
    expect(link).toHaveAttribute('aria-current', 'page');
    await screen.findByText('API reachable');
  });

  it('lists Alerts as not yet available rather than as a dead link', async () => {
    renderApp();

    expect(screen.queryByRole('link', { name: /alerts/i })).not.toBeInTheDocument();
    const nav = screen.getByRole('navigation', { name: 'Primary' });
    const pending = within(nav).getByText('Alerts').closest('[aria-disabled="true"]');
    expect(pending).not.toBeNull();
    expect(pending).toHaveTextContent('Soon');
    await screen.findByText('API reachable');
  });

  it('shows the read-only / not-a-confirmed-attack footer', async () => {
    renderApp();

    expect(screen.getByRole('contentinfo')).toHaveTextContent(/read-only view/i);
    expect(screen.getByRole('contentinfo')).toHaveTextContent(/not a confirmed attack/i);
    await screen.findByText('API reachable');
  });

  it('renders the overview page at the root route', async () => {
    renderApp('/');

    expect(screen.getByRole('heading', { level: 1, name: 'Overview' })).toBeInTheDocument();
    await screen.findByText('API reachable');
  });

  it('shows a not-found page, inside the shell, for an unknown route', async () => {
    renderApp('/nowhere');

    expect(screen.getByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to the overview' })).toHaveAttribute('href', '/');
    expect(screen.getByRole('navigation', { name: 'Primary' })).toBeInTheDocument();
    await screen.findByText('API reachable');
  });
});

describe('ConfigErrorPage', () => {
  it('names the setting and the problem, and says how to fix it', () => {
    render(<ConfigErrorPage reason="must use http or https." />);

    const alert = screen.getByRole('alert');
    expect(within(alert).getByRole('heading', { name: 'Dashboard configuration error' })).toBeInTheDocument();
    expect(alert).toHaveTextContent('VITE_API_BASE_URL');
    expect(alert).toHaveTextContent('must use http or https.');
    expect(alert).toHaveTextContent(/restart the dev server or rebuild/i);
  });
});
