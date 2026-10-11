import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
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

  it('lists Overview and Alerts as links, and neither is marked "Soon"', async () => {
    renderApp();

    const nav = screen.getByRole('navigation', { name: 'Primary' });
    expect(within(nav).getByRole('link', { name: 'Overview' })).toHaveAttribute('href', '/');
    expect(within(nav).getByRole('link', { name: 'Alerts' })).toHaveAttribute('href', '/alerts');
    expect(within(nav).queryByText('Soon')).not.toBeInTheDocument();
    expect(nav.querySelector('[aria-disabled="true"]')).toBeNull();
    await screen.findByText('API reachable');
  });

  it('marks only the Alerts link as current on the alerts page', async () => {
    renderApp('/alerts');

    const nav = screen.getByRole('navigation', { name: 'Primary' });
    expect(within(nav).getByRole('link', { name: 'Alerts' })).toHaveAttribute('aria-current', 'page');
    expect(within(nav).getByRole('link', { name: 'Overview' })).not.toHaveAttribute('aria-current');
    await screen.findByText('API reachable');
  });

  it('does not mark Alerts as current on the overview page', async () => {
    renderApp('/');

    const nav = screen.getByRole('navigation', { name: 'Primary' });
    expect(within(nav).getByRole('link', { name: 'Alerts' })).not.toHaveAttribute('aria-current');
    await screen.findByText('API reachable');
  });

  it('moves between the overview and the alerts page with the navigation links', async () => {
    const user = userEvent.setup();
    renderApp('/');
    const nav = screen.getByRole('navigation', { name: 'Primary' });

    await user.click(within(nav).getByRole('link', { name: 'Alerts' }));
    expect(await screen.findByRole('heading', { level: 1, name: 'Alerts' })).toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'Persisted alerts, newest first' })).toBeInTheDocument();

    await user.click(within(nav).getByRole('link', { name: 'Overview' }));
    expect(await screen.findByRole('heading', { level: 1, name: 'Overview' })).toBeInTheDocument();
    expect(await screen.findByRole('article', { name: 'Persisted alerts' })).toBeInTheDocument();
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
