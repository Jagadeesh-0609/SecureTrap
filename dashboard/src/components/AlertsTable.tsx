import { Link } from 'react-router-dom';

import type { AlertResponse } from '../api/types';
import { COPY } from '../copy';
import { formatScore, showInvisibleCharacters, truncate } from '../utils/format';
import { AlertTime } from './AlertTime';

const COMMAND_PREVIEW_LENGTH = 80;

/** What the list passes to the detail page, so "Back to alerts" can restore the filters. */
export interface AlertLinkState {
  /** The list's query string, e.g. "?q=wget"; empty when no filters are set. */
  from: string;
}

interface AlertsTableProps {
  alerts: readonly AlertResponse[];
  /** The list's current query string, handed to the detail page. */
  listSearch: string;
}

function commandPreview(command: string): string {
  return truncate(showInvisibleCharacters(command).replace(/\s+/g, ' ').trim(), COMMAND_PREVIEW_LENGTH);
}

/** A short, safe-to-display version of a text field from the honeypot. */
function cellText(value: string): string {
  return truncate(showInvisibleCharacters(value), 64);
}

/**
 * The alerts as a table. Every cell is plain text (React escapes it), and the
 * long or attacker-controlled ones are shortened; the detail page shows them
 * in full. On narrow screens the table scrolls sideways inside a focusable
 * region instead of squeezing its columns.
 */
export function AlertsTable({ alerts, listSearch }: AlertsTableProps) {
  const t = COPY.alerts.table;
  const linkState: AlertLinkState = { from: listSearch };

  return (
    <div className="table-scroll" role="region" aria-label={t.scrollLabel} tabIndex={0}>
      <table className="alerts-table">
        <caption className="visually-hidden">{t.caption}</caption>
        <thead>
          <tr>
            <th scope="col">{t.id}</th>
            <th scope="col">{t.time}</th>
            <th scope="col">{t.eventType}</th>
            <th scope="col">{t.sourceIp}</th>
            <th scope="col">{t.command}</th>
            <th scope="col" className="alerts-table__number">
              {t.score}
            </th>
            <th scope="col">{t.flag}</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => {
            const preview = commandPreview(alert.command);
            return (
              <tr key={alert.id}>
                <th scope="row">
                  <Link to={`/alerts/${alert.id}`} state={linkState} aria-label={`${t.open} #${alert.id}`}>
                    #{alert.id}
                  </Link>
                </th>
                <td className="alerts-table__nowrap">
                  <AlertTime timestamp={alert.timestamp} />
                </td>
                <td className="alerts-table__nowrap untrusted-text">{cellText(alert.event_type)}</td>
                <td className="alerts-table__nowrap alerts-table__mono untrusted-text">{cellText(alert.source_ip)}</td>
                <td className="alerts-table__command">
                  {preview === '' ? (
                    <span className="muted">{t.noCommand}</span>
                  ) : (
                    <code className="untrusted-text">{preview}</code>
                  )}
                </td>
                <td className="alerts-table__number">{formatScore(alert.score)}</td>
                <td>
                  <span className={alert.is_anomaly ? 'flag flag--on' : 'flag flag--off'}>
                    {alert.is_anomaly ? t.flagged : t.notFlagged}
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
