import { useIsFetching, useQueryClient } from '@tanstack/react-query';

import { LoadFailure } from '../components/LoadFailure';
import { RefreshControl } from '../components/RefreshControl';
import { ScopeBanner } from '../components/ScopeBanner';
import { StaleNotice } from '../components/StaleNotice';
import { StatePanel } from '../components/StatePanel';
import { SummaryCards } from '../components/SummaryCards';
import { SummarySkeleton } from '../components/SummarySkeleton';
import { COPY } from '../copy';
import { useAlertSummary } from '../hooks/useAlertSummary';
import { deriveOverviewState } from './overviewState';

/**
 * The landing page: headline figures from GET /api/v1/alerts/summary.
 *
 * Exactly one of loading / unavailable / error / empty / ready is shown,
 * chosen by deriveOverviewState().
 */
export function OverviewPage() {
  const summary = useAlertSummary();
  const queryClient = useQueryClient();
  const isRefreshing = useIsFetching() > 0;

  const view = deriveOverviewState({
    data: summary.data,
    error: summary.error,
    isPending: summary.isPending,
  });

  const refresh = () => {
    void queryClient.refetchQueries({ type: 'active' });
  };

  return (
    <>
      <div className="page-heading">
        <h1>{COPY.overview.title}</h1>
        <RefreshControl
          updatedAt={summary.dataUpdatedAt}
          isRefreshing={isRefreshing}
          onRefresh={refresh}
        />
      </div>
      <p className="page-hint">{COPY.overview.autoRefresh}</p>

      <ScopeBanner />

      {view.kind === 'loading' ? <SummarySkeleton /> : null}

      {view.kind === 'unavailable' || view.kind === 'error' ? (
        <LoadFailure error={view.error} onRetry={refresh} />
      ) : null}

      {view.kind === 'empty' ? (
        <>
          {view.refreshError ? (
            <StaleNotice updatedAt={summary.dataUpdatedAt} error={view.refreshError} />
          ) : null}
          <StatePanel tone="info" title={COPY.states.empty.title}>
            <p>{COPY.states.empty.body}</p>
            <p>{COPY.states.empty.detail}</p>
          </StatePanel>
        </>
      ) : null}

      {view.kind === 'ready' ? (
        <section aria-labelledby="summary-heading">
          <h2 id="summary-heading" className="section-heading">
            {COPY.overview.summaryHeading}
          </h2>
          {view.refreshError ? (
            <StaleNotice updatedAt={summary.dataUpdatedAt} error={view.refreshError} />
          ) : null}
          <SummaryCards summary={view.summary} />
        </section>
      ) : null}
    </>
  );
}
