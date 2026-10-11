import { COPY } from '../copy';

/** Placeholder rows shown while the first alerts request is in flight. */
export function AlertsSkeleton() {
  return (
    <div role="status" aria-live="polite" aria-busy="true">
      <span className="visually-hidden">{COPY.alerts.states.loading}</span>
      <div className="alerts-skeleton" aria-hidden="true">
        {[0, 1, 2, 3, 4, 5].map((index) => (
          <div key={index} className="skeleton alerts-skeleton__row" />
        ))}
      </div>
    </div>
  );
}
