import { NavLink } from 'react-router-dom';

import { COPY } from '../../copy';

type NavItem =
  | { label: string; enabled: true; to: string }
  | { label: string; enabled: false };

/**
 * The primary navigation. Later phases switch an item to `enabled: true` and
 * register its route in App.tsx; nothing else here needs to change.
 */
const NAV_ITEMS: readonly NavItem[] = [
  { label: COPY.nav.overview, enabled: true, to: '/' },
  { label: COPY.nav.alerts, enabled: false },
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
                end
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
