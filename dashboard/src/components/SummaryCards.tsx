import type { AlertSummaryResponse } from '../api/types';
import { COPY } from '../copy';
import { formatCount, formatRatioAsPercent } from '../utils/format';
import { SummaryCard } from './SummaryCard';

/**
 * The four headline figures from GET /api/v1/alerts/summary.
 *
 * Every figure describes PERSISTED alert records; the captions say so. The
 * anomaly share is shown as a percentage of persisted records only.
 */
export function SummaryCards({ summary }: { summary: AlertSummaryResponse }) {
  const everyRecordIsFlagged = summary.total_alerts > 0 && summary.normal_count === 0;

  return (
    <>
      <div className="summary-grid">
        <SummaryCard
          label={COPY.cards.total.label}
          value={formatCount(summary.total_alerts)}
          caption={COPY.cards.total.caption}
        />
        <SummaryCard
          label={COPY.cards.anomalies.label}
          value={formatCount(summary.anomaly_count)}
          caption={COPY.cards.anomalies.caption}
        />
        <SummaryCard
          label={COPY.cards.normal.label}
          value={formatCount(summary.normal_count)}
          caption={COPY.cards.normal.caption}
        />
        <SummaryCard
          label={COPY.cards.rate.label}
          value={formatRatioAsPercent(summary.anomaly_rate)}
          caption={COPY.cards.rate.caption}
        />
      </div>
      {everyRecordIsFlagged ? (
        <p className="summary-note" role="note">
          {COPY.cards.allFlaggedNote}
        </p>
      ) : null}
    </>
  );
}
