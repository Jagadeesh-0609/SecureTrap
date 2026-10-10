import { useId } from 'react';

import { COPY } from '../copy';

/**
 * Always-visible statement of what the figures on a page mean. It is shown
 * on the page itself, not tucked into a tooltip, so nobody reads a
 * persisted-record count as a statement about all traffic.
 */
export function ScopeBanner() {
  const headingId = useId();
  return (
    <aside className="scope-banner" aria-labelledby={headingId}>
      <h2 id={headingId} className="scope-banner__heading">
        {COPY.scope.heading}
      </h2>
      <p>{COPY.scope.persisted}</p>
      <p>{COPY.scope.semantics}</p>
    </aside>
  );
}
