import { useId } from 'react';

import { COPY } from '../copy';
import { toFlagFilter, type AlertFilters } from '../pages/alertsFilter';
import { showInvisibleCharacters, truncate } from '../utils/format';

interface AlertsFilterBarProps {
  filters: AlertFilters;
  /** Event types present in the loaded alerts. */
  eventTypes: readonly string[];
  /** Offer the event-type filter (only worth showing when there is a choice). */
  showEventType: boolean;
  /** Offer the anomaly-flag filter (only worth showing when both kinds are present). */
  showFlag: boolean;
  canClear: boolean;
  onChange: (next: Partial<AlertFilters>) => void;
  onClear: () => void;
}

/** Search box and the filters that the loaded data can actually support. */
export function AlertsFilterBar({
  filters,
  eventTypes,
  showEventType,
  showFlag,
  canClear,
  onChange,
  onClear,
}: AlertsFilterBarProps) {
  const searchId = useId();
  const hintId = useId();
  const eventTypeId = useId();
  const flagId = useId();
  const t = COPY.alerts.filters;

  return (
    <form
      className="filter-bar"
      role="search"
      aria-label={t.label}
      onSubmit={(event) => event.preventDefault()}
    >
      <div className="field field--grow">
        <label htmlFor={searchId}>{t.search}</label>
        <input
          id={searchId}
          className="input"
          type="search"
          value={filters.query}
          placeholder={t.searchPlaceholder}
          aria-describedby={hintId}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => onChange({ query: event.target.value })}
        />
        <p id={hintId} className="field__hint">
          {t.searchHint}
        </p>
      </div>

      {showEventType ? (
        <div className="field">
          <label htmlFor={eventTypeId}>{t.eventType}</label>
          <select
            id={eventTypeId}
            className="input"
            value={filters.eventType}
            onChange={(event) => onChange({ eventType: event.target.value })}
          >
            <option value="">{t.allEventTypes}</option>
            {eventTypes.map((eventType) => (
              <option key={eventType} value={eventType}>
                {truncate(showInvisibleCharacters(eventType), 64)}
              </option>
            ))}
          </select>
        </div>
      ) : null}

      {showFlag ? (
        <div className="field">
          <label htmlFor={flagId}>{t.flag}</label>
          <select
            id={flagId}
            className="input"
            value={filters.flag}
            onChange={(event) => onChange({ flag: toFlagFilter(event.target.value) })}
          >
            <option value="all">{t.allFlags}</option>
            <option value="flagged">{t.flagged}</option>
            <option value="notFlagged">{t.notFlagged}</option>
          </select>
        </div>
      ) : null}

      <div className="field field--action">
        <button type="button" className="button" onClick={onClear} disabled={!canClear}>
          {t.clear}
        </button>
      </div>
    </form>
  );
}
