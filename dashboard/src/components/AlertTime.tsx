import { formatAlertTimestamp, parseAlertTimestamp, showInvisibleCharacters, truncate } from '../utils/format';

/**
 * An alert's event time as readable UTC text. A timestamp that is not an
 * unambiguous ISO 8601 date-time is shown exactly as recorded, never guessed.
 */
export function AlertTime({ timestamp }: { timestamp: string }) {
  const date = parseAlertTimestamp(timestamp);
  if (date === null) {
    return <span className="untrusted-text">{truncate(showInvisibleCharacters(timestamp), 64)}</span>;
  }
  return (
    <time dateTime={date.toISOString()} title={timestamp}>
      {formatAlertTimestamp(timestamp)}
    </time>
  );
}
