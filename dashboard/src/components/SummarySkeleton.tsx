import { COPY } from '../copy';

/** Placeholder cards shown while the first summary request is in flight. */
export function SummarySkeleton() {
  return (
    <div role="status" aria-live="polite" aria-busy="true">
      <span className="visually-hidden">{COPY.states.loading}</span>
      <div className="summary-grid" aria-hidden="true">
        {[0, 1, 2, 3].map((index) => (
          <div key={index} className="summary-card summary-card--skeleton">
            <div className="skeleton skeleton--label" />
            <div className="skeleton skeleton--value" />
            <div className="skeleton skeleton--caption" />
          </div>
        ))}
      </div>
    </div>
  );
}
