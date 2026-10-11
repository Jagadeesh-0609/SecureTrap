import type { AlertResponse } from '../api/types';
import { COPY } from '../copy';
import { formatScore, formatTemplate, showInvisibleCharacters } from '../utils/format';
import { AlertTime } from './AlertTime';

/** The model's raw prediction, named the way the model defines it. */
function describePrediction(prediction: number): string {
  if (prediction === -1) {
    return COPY.alertDetail.predictionOutlier;
  }
  if (prediction === 1) {
    return COPY.alertDetail.predictionInlier;
  }
  return formatTemplate(COPY.alertDetail.predictionOther, { value: prediction });
}

/**
 * Every field the API returns for one alert, as a description list. All
 * values are plain text nodes. The command is attacker-controlled, so it is
 * labelled as untrusted and shown in a preformatted block that wraps instead
 * of widening the page.
 */
export function AlertFields({ alert }: { alert: AlertResponse }) {
  const f = COPY.alertDetail.fields;
  const show = showInvisibleCharacters;

  return (
    <dl className="detail-list">
      <div className="detail-list__row">
        <dt>{f.id}</dt>
        <dd>{alert.id}</dd>
      </div>
      <div className="detail-list__row">
        <dt>{f.time}</dt>
        <dd>
          <AlertTime timestamp={alert.timestamp} />
        </dd>
      </div>
      <div className="detail-list__row">
        <dt>{f.timestamp}</dt>
        <dd>
          <code className="untrusted-text">{show(alert.timestamp)}</code>
        </dd>
      </div>
      <div className="detail-list__row">
        <dt>{f.sourceIp}</dt>
        <dd>
          <code className="untrusted-text">{show(alert.source_ip)}</code>
        </dd>
      </div>
      <div className="detail-list__row">
        <dt>{f.sessionId}</dt>
        <dd>
          <code className="untrusted-text">{show(alert.session_id)}</code>
        </dd>
      </div>
      <div className="detail-list__row">
        <dt>{f.protocol}</dt>
        <dd className="untrusted-text">{show(alert.protocol)}</dd>
      </div>
      <div className="detail-list__row">
        <dt>{f.honeypot}</dt>
        <dd className="untrusted-text">{show(alert.honeypot)}</dd>
      </div>
      <div className="detail-list__row">
        <dt>{f.eventType}</dt>
        <dd>
          <code className="untrusted-text">{show(alert.event_type)}</code>
        </dd>
      </div>
      <div className="detail-list__row detail-list__row--wide">
        <dt>{f.command}</dt>
        <dd>
          {alert.command === '' ? (
            <span className="muted">{COPY.alertDetail.noCommand}</span>
          ) : (
            <pre className="command-block untrusted-text">
              <code>{show(alert.command)}</code>
            </pre>
          )}
          <p className="detail-list__note">{COPY.alertDetail.commandNote}</p>
        </dd>
      </div>
      <div className="detail-list__row">
        <dt>{f.prediction}</dt>
        <dd>{describePrediction(alert.prediction)}</dd>
      </div>
      <div className="detail-list__row">
        <dt>{f.score}</dt>
        <dd>
          {formatScore(alert.score)}
          <p className="detail-list__note">{COPY.alertDetail.scoreNote}</p>
        </dd>
      </div>
      <div className="detail-list__row">
        <dt>{f.flag}</dt>
        <dd>
          <span className={alert.is_anomaly ? 'flag flag--on' : 'flag flag--off'}>
            {alert.is_anomaly ? COPY.alertDetail.flagged : COPY.alertDetail.notFlagged}
          </span>
        </dd>
      </div>
    </dl>
  );
}
