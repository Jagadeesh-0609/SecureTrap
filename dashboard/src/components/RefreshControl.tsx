import { COPY } from '../copy';
import { formatTime } from '../utils/format';

interface RefreshControlProps {
  /** Epoch ms of the last successful fetch, or 0 / undefined if none yet. */
  updatedAt: number | undefined;
  isRefreshing: boolean;
  onRefresh: () => void;
}

/** "Updated HH:MM:SS" plus a manual refresh button. */
export function RefreshControl({ updatedAt, isRefreshing, onRefresh }: RefreshControlProps) {
  const hasUpdate = updatedAt !== undefined && updatedAt > 0;
  return (
    <div className="refresh-control">
      {hasUpdate ? (
        <span className="refresh-control__updated">
          {COPY.overview.updated}{' '}
          <time dateTime={new Date(updatedAt).toISOString()}>{formatTime(updatedAt)}</time>
        </span>
      ) : null}
      <button type="button" className="button" onClick={onRefresh} disabled={isRefreshing}>
        {isRefreshing ? COPY.overview.refreshing : COPY.overview.refresh}
      </button>
    </div>
  );
}
