import { useMemo, useState } from 'react';
import { useLocation, useNavigationType, useSearchParams } from 'react-router-dom';

import type { AlertResponse } from '../api/types';
import { ALERT_LIST_LIMIT } from '../api/endpoints';
import { AlertsFilterBar } from '../components/AlertsFilterBar';
import { AlertsSkeleton } from '../components/AlertsSkeleton';
import { AlertsTable } from '../components/AlertsTable';
import { LoadFailure } from '../components/LoadFailure';
import { RefreshControl } from '../components/RefreshControl';
import { StaleNotice } from '../components/StaleNotice';
import { StatePanel } from '../components/StatePanel';
import { COPY } from '../copy';
import { useAlerts } from '../hooks/useAlerts';
import { useHeadingFocus } from '../hooks/useHeadingFocus';
import { formatCount, formatTemplate } from '../utils/format';
import {
  NO_FILTERS,
  buildSearchIndex,
  distinctEventTypes,
  filterAlerts,
  hasActiveFilters,
  hasBothFlags,
  readFilters,
  writeFilters,
  type AlertFilters,
} from './alertsFilter';
import { deriveAlertsState } from './alertsState';

const NO_ALERTS: readonly AlertResponse[] = [];

const failureMessages = {
  unavailable: COPY.alerts.states.unavailableBody,
  httpError: COPY.alerts.states.httpErrorBody,
};

/**
 * The alerts list: GET /api/v1/alerts, filtered in the browser.
 *
 * The list endpoint only takes a `limit`, so search and filters run over the
 * alerts already loaded and never trigger another request. The filters live in
 * the address bar (?q=, ?type=, ?flag=) so they survive opening an alert and
 * coming back, and so a filtered view can be shared as a link.
 */
export function AlertsPage() {
  const alertsQuery = useAlerts();
  const headingRef = useHeadingFocus();
  const [searchParams, setSearchParams] = useSearchParams();
  const location = useLocation();
  const navigationType = useNavigationType();

  // What the user asked for (before checking it against the loaded data).
  const [requested, setRequested] = useState<AlertFilters>(() => readFilters(searchParams));

  // Follow the address bar when it changes from outside this page (a click on
  // the Alerts link, the browser's back or forward buttons). This page's own
  // edits are "replace" navigations and are skipped: it already has that state.
  const [seenLocationKey, setSeenLocationKey] = useState(location.key);
  if (location.key !== seenLocationKey) {
    setSeenLocationKey(location.key);
    if (navigationType !== 'REPLACE') {
      setRequested(readFilters(searchParams));
    }
  }

  const view = deriveAlertsState({ data: alertsQuery.data, error: alertsQuery.error });
  const alerts = view.kind === 'ready' ? view.alerts : NO_ALERTS;

  const searchIndex = useMemo(() => buildSearchIndex(alerts), [alerts]);
  const eventTypes = useMemo(() => distinctEventTypes(alerts), [alerts]);
  const showEventType = eventTypes.length > 1;
  const showFlag = useMemo(() => hasBothFlags(alerts), [alerts]);

  // Only filters the loaded data can support are applied (a ?type= that
  // matches nothing, or ?flag= when every record has the same flag, is ignored).
  const filters: AlertFilters = {
    query: requested.query,
    eventType: showEventType && eventTypes.includes(requested.eventType) ? requested.eventType : '',
    flag: showFlag ? requested.flag : 'all',
  };
  const active = hasActiveFilters(filters);

  const { query, eventType, flag } = filters;
  const visible = useMemo(
    () => filterAlerts(searchIndex, { query, eventType, flag }),
    [searchIndex, query, eventType, flag],
  );

  const updateFilters = (changes: Partial<AlertFilters>) => {
    const next = { ...requested, ...changes };
    setRequested(next);
    setSearchParams(writeFilters(next), { replace: true });
  };
  const clearFilters = () => updateFilters(NO_FILTERS);

  const refresh = () => {
    void alertsQuery.refetch();
  };

  const total = alerts.length;
  const countTemplate = active
    ? total === 1
      ? COPY.alerts.showingOne
      : COPY.alerts.showingMany
    : total === 1
      ? COPY.alerts.countOne
      : COPY.alerts.countMany;
  const countText = formatTemplate(countTemplate, {
    shown: formatCount(visible.length),
    count: formatCount(total),
  });

  return (
    <>
      <div className="page-heading">
        <h1 ref={headingRef} tabIndex={-1}>
          {COPY.alerts.title}
        </h1>
        <RefreshControl
          updatedAt={alertsQuery.dataUpdatedAt}
          isRefreshing={alertsQuery.isFetching}
          onRefresh={refresh}
        />
      </div>
      <p className="page-hint">{COPY.alerts.intro}</p>
      <p className="page-hint">{COPY.alerts.refreshHint}</p>
      <p className="page-note">{COPY.alerts.semantics}</p>

      {view.kind === 'loading' ? <AlertsSkeleton /> : null}

      {view.kind === 'unavailable' || view.kind === 'error' ? (
        <LoadFailure error={view.error} onRetry={refresh} messages={failureMessages} />
      ) : null}

      {view.kind === 'empty' ? (
        <>
          {view.refreshError ? (
            <StaleNotice updatedAt={alertsQuery.dataUpdatedAt} error={view.refreshError} />
          ) : null}
          <StatePanel tone="info" title={COPY.alerts.states.empty.title}>
            <p>{COPY.alerts.states.empty.body}</p>
            <p>{COPY.states.empty.detail}</p>
          </StatePanel>
        </>
      ) : null}

      {view.kind === 'ready' ? (
        <section aria-label={COPY.alerts.table.caption} className="alerts-section">
          {view.refreshError ? (
            <StaleNotice updatedAt={alertsQuery.dataUpdatedAt} error={view.refreshError} />
          ) : null}

          <AlertsFilterBar
            filters={filters}
            eventTypes={eventTypes}
            showEventType={showEventType}
            showFlag={showFlag}
            canClear={active}
            onChange={updateFilters}
            onClear={clearFilters}
          />

          <p className="count-line" role="status">
            {countText}
          </p>
          {total >= ALERT_LIST_LIMIT ? (
            <p className="page-hint">{formatTemplate(COPY.alerts.limitNote, { limit: ALERT_LIST_LIMIT })}</p>
          ) : null}

          {visible.length === 0 ? (
            <StatePanel
              tone="info"
              title={COPY.alerts.noResults.title}
              actions={
                <button type="button" className="button" onClick={clearFilters}>
                  {COPY.alerts.filters.clear}
                </button>
              }
            >
              <p>{formatTemplate(COPY.alerts.noResults.body, { count: formatCount(total) })}</p>
            </StatePanel>
          ) : (
            <AlertsTable alerts={visible} listSearch={searchString(requested)} />
          )}
        </section>
      ) : null}
    </>
  );
}

/** The list's query string ("?q=wget" or "") as the address bar holds it. */
function searchString(filters: AlertFilters): string {
  const text = writeFilters(filters).toString();
  return text === '' ? '' : `?${text}`;
}
