import { Outlet } from 'react-router-dom';

import { COPY } from '../../copy';
import { ApiStatus } from '../ApiStatus';
import { NavBar } from './NavBar';

/** Inline decorative mark: concentric rings around a point (a "trap"). */
function BrandMark() {
  return (
    <svg className="brand__mark" viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <circle cx="16" cy="16" r="13" />
      <circle cx="16" cy="16" r="7" />
      <circle cx="16" cy="16" r="1.5" className="brand__mark-dot" />
    </svg>
  );
}

/** Page chrome shared by every route: header, navigation, content, footer. */
export function AppShell() {
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <header className="app-header">
        <div className="brand">
          <BrandMark />
          <span className="brand__name">{COPY.brand.name}</span>
          <span className="brand__product">{COPY.brand.product}</span>
        </div>
        <NavBar />
        <ApiStatus />
      </header>
      <main id="main-content" className="app-main" tabIndex={-1}>
        <Outlet />
      </main>
      <footer className="app-footer">{COPY.footer}</footer>
    </div>
  );
}
