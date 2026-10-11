import { NavLink } from 'react-router-dom';

import { COPY } from '../../copy';

type NavItem =
  | { label: string; enabled: true; to: string }
  | { label: string; enabled: false };

/**
 * The primary navigation. An item that is not built yet is listed with
 * `enabled: false` (shown as "Soon", not focusable); a later phase switches
 * it on and registers its route in App.tsx.
 */
const NAV_ITEMS: readonly NavItem[] = [
  { label: COPY.nav.overview, enabled: true, to: '/' },
  { label: COPY.nav.alerts, enabled: true, to: '/alerts' },
];

export function NavBar() {
  return (
    <nav className="nav" aria-label="Primary">
      <ul className="nav__list">
        {NAV_ITEMS.map((item) => (
          <li key={item.label}>
            {item.enabled ? (
              <NavLink
                to={item.to}
                className={({ isActive }) =>
                  isActive ? 'nav__link nav__link--active' : 'nav__link'
                }
              >
                {item.label}
              </NavLink>
            ) : (
              <span className="nav__link nav__link--disabled" aria-disabled="true">
                {item.label}
                <span className="nav__badge">{COPY.nav.soon}</span>
              </span>
            )}
          </li>
        ))}
      </ul>
    </nav>
  );
}
