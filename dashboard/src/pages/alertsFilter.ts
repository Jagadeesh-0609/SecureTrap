import type { AlertResponse } from '../api/types';

/** Which records to show by their anomaly flag. */
export type FlagFilter = 'all' | 'flagged' | 'notFlagged';

export interface AlertFilters {
  /** Free-text search; empty means no search. */
  query: string;
  /** An exact event type, or '' for all. */
  eventType: string;
  flag: FlagFilter;
}

/** Anything other than the two real flag choices means "all". */
export function toFlagFilter(value: string | null): FlagFilter {
  return value === 'flagged' || value === 'notFlagged' ? value : 'all';
}

export const NO_FILTERS: AlertFilters = { query: '', eventType: '', flag: 'all' };

const MAX_QUERY_LENGTH = 200;

/** The fields the search looks through. Everything shown in the table, and more. */
function searchableText(alert: AlertResponse): string {
  return [
    alert.id,
    alert.timestamp,
    alert.source_ip,
    alert.session_id,
    alert.protocol,
    alert.honeypot,
    alert.event_type,
    alert.command,
  ]
    .map((value) => (value === null || value === undefined ? '' : String(value)))
    .join('\n')
    .toLowerCase();
}

function searchTerms(query: string): string[] {
  return query.toLowerCase().split(/\s+/).filter(Boolean);
}

export interface SearchableAlert {
  alert: AlertResponse;
  text: string;
}

/** Lower-cased search text for each alert, computed once per loaded list. */
export function buildSearchIndex(alerts: readonly AlertResponse[]): SearchableAlert[] {
  return alerts.map((alert) => ({ alert, text: searchableText(alert) }));
}

/**
 * Apply the filters. Search is case-insensitive and every whitespace-separated
 * word must appear somewhere in the alert (any order), so "ssh wget" finds a
 * wget command from an ssh session.
 */
export function filterAlerts(index: readonly SearchableAlert[], filters: AlertFilters): AlertResponse[] {
  const terms = searchTerms(filters.query);
  return index
    .filter(({ alert, text }) => {
      if (filters.eventType !== '' && alert.event_type !== filters.eventType) {
        return false;
      }
      if (filters.flag === 'flagged' && !alert.is_anomaly) {
        return false;
      }
      if (filters.flag === 'notFlagged' && alert.is_anomaly) {
        return false;
      }
      return terms.every((term) => text.includes(term));
    })
    .map(({ alert }) => alert);
}

/** The distinct event types present, sorted, for the event-type filter. */
export function distinctEventTypes(alerts: readonly AlertResponse[]): string[] {
  return [...new Set(alerts.map((alert) => alert.event_type))].sort((a, b) => a.localeCompare(b));
}

/** True when both flagged and non-flagged records are present. */
export function hasBothFlags(alerts: readonly AlertResponse[]): boolean {
  return alerts.some((alert) => alert.is_anomaly) && alerts.some((alert) => !alert.is_anomaly);
}

export function hasActiveFilters(filters: AlertFilters): boolean {
  return filters.query.trim() !== '' || filters.eventType !== '' || filters.flag !== 'all';
}

const QUERY_PARAM = 'q';
const EVENT_TYPE_PARAM = 'type';
const FLAG_PARAM = 'flag';

/** Read filters from the address bar's query string. Unknown values are ignored. */
export function readFilters(params: URLSearchParams): AlertFilters {
  return {
    query: (params.get(QUERY_PARAM) ?? '').slice(0, MAX_QUERY_LENGTH),
    eventType: params.get(EVENT_TYPE_PARAM) ?? '',
    flag: toFlagFilter(params.get(FLAG_PARAM)),
  };
}

/** The query string for the given filters; default values are left out. */
export function writeFilters(filters: AlertFilters): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.query !== '') {
    params.set(QUERY_PARAM, filters.query.slice(0, MAX_QUERY_LENGTH));
  }
  if (filters.eventType !== '') {
    params.set(EVENT_TYPE_PARAM, filters.eventType);
  }
  if (filters.flag !== 'all') {
    params.set(FLAG_PARAM, filters.flag);
  }
  return params;
}
