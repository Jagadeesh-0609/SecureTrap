import { COPY } from '../copy';
import { describeError } from '../pages/overviewState';
import { formatTime } from '../utils/format';

/** Shown above still-visible data when the most recent refresh failed. */
export function StaleNotice({ updatedAt, error }: { updatedAt: number; error: Error }) {
  return (
    <p className="stale-notice" role="status">
      {COPY.states.stale.lead}{' '}
      <time dateTime={new Date(updatedAt).toISOString()}>{formatTime(updatedAt)}</time>.{' '}
      {COPY.states.stale.reason} {describeError(error)}
    </p>
  );
}
