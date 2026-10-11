import { Link, useLocation, useParams } from 'react-router-dom';

import { AlertFields } from '../components/AlertFields';
import { LoadFailure } from '../components/LoadFailure';
import { StatePanel } from '../components/StatePanel';
import { COPY } from '../copy';
import { useAlertDetail } from '../hooks/useAlertDetail';
import { useHeadingFocus } from '../hooks/useHeadingFocus';
import { formatTemplate } from '../utils/format';
import { parseAlertIdParam } from '../utils/alertId';

const failureMessages = {
  unavailable: COPY.alertDetail.states.unavailableBody,
  httpError: COPY.alertDetail.states.httpErrorBody,
};

/** The list's query string, if the list handed it over; anything else is ignored. */
function listSearchFrom(state: unknown): string {
  if (typeof state === 'object' && state !== null && 'from' in state) {
    const { from } = state;
    if (typeof from === 'string' && /^(\?[^#\s]*)?$/.test(from)) {
      return from;
    }
  }
  return '';
}

/**
 * One persisted alert: GET /api/v1/alerts/{alert_id}.
 *
 * The ID comes from the address bar, so it is validated as a plain positive
 * whole number before it can reach a request; anything else shows an
 * "invalid ID" message and makes no request at all.
 */
export function AlertDetailPage() {
  const { alertId: rawAlertId } = useParams();
  const alertId = parseAlertIdParam(rawAlertId);
  const detail = useAlertDetail(alertId);
  const headingRef = useHeadingFocus();
  const location = useLocation();
  const backTarget = { pathname: '/alerts', search: listSearchFrom(location.state) };

  const title = alertId === null ? COPY.alertDetail.title : `${COPY.alertDetail.title} #${alertId}`;
  const back = (
    <p className="back-link">
      <Link to={backTarget}>{COPY.alertDetail.back}</Link>
    </p>
  );

  let body;
  if (alertId === null) {
    body = (
      <StatePanel tone="warning" title={COPY.alertDetail.states.invalidId.title}>
        <p>{COPY.alertDetail.states.invalidId.body}</p>
      </StatePanel>
    );
  } else if (detail.data?.found === true) {
    body = (
      <>
        <p className="page-note">{COPY.alertDetail.semantics}</p>
        <AlertFields alert={detail.data.alert} />
      </>
    );
  } else if (detail.data?.found === false) {
    body = (
      <StatePanel tone="info" title={COPY.alertDetail.states.notFound.title}>
        <p>{formatTemplate(COPY.alertDetail.states.notFound.body, { id: alertId })}</p>
      </StatePanel>
    );
  } else if (detail.error !== null) {
    body = (
      <LoadFailure
        error={detail.error}
        onRetry={() => {
          void detail.refetch();
        }}
        messages={failureMessages}
      />
    );
  } else {
    body = (
      <div role="status" aria-live="polite" aria-busy="true">
        <span className="visually-hidden">{COPY.alertDetail.states.loading}</span>
        <div className="alerts-skeleton" aria-hidden="true">
          {[0, 1, 2, 3].map((index) => (
            <div key={index} className="skeleton alerts-skeleton__row" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <>
      {back}
      <h1 ref={headingRef} tabIndex={-1}>
        {title}
      </h1>
      {body}
    </>
  );
}
