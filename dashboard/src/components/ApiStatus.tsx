import { ApiError } from '../api/client';
import { COPY } from '../copy';
import { useHealth } from '../hooks/useHealth';
import { truncate } from '../utils/format';

type StatusState = 'checking' | 'reachable' | 'unreachable' | 'error' | 'unexpected';

interface StatusView {
  state: StatusState;
  label: string;
  description: string;
}

/**
 * Header indicator driven by GET /health.
 *
 * It reports only that the API process answered. It deliberately never says
 * "healthy": /health performs no database, detector or honeypot check, so a
 * green indicator here says nothing about whether detection is running.
 */
export function ApiStatus() {
  const { data, error, isPending } = useHealth();
  const view = describeHealth({ data, error, isPending });

  return (
    <div className="api-status" role="status" data-state={view.state} title={view.description}>
      <span className="api-status__dot" aria-hidden="true" />
      <span className="api-status__label">{view.label}</span>
      <span className="visually-hidden">{view.description}</span>
    </div>
  );
}

function describeHealth(input: {
  data: { status: string } | undefined;
  error: Error | null;
  isPending: boolean;
}): StatusView {
  const { data, error, isPending } = input;

  if (error !== null) {
    if (error instanceof ApiError && error.kind === 'http') {
      return {
        state: 'error',
        label: `API error (HTTP ${error.status ?? '?'})`,
        description: COPY.apiStatus.httpErrorDetail,
      };
    }
    if (error instanceof ApiError && error.kind === 'invalid') {
      return {
        state: 'unexpected',
        label: COPY.apiStatus.unexpected,
        description: COPY.apiStatus.invalidDetail,
      };
    }
    return {
      state: 'unreachable',
      label: COPY.apiStatus.unreachable,
      description: COPY.apiStatus.unreachableDetail,
    };
  }

  if (data === undefined || isPending) {
    return {
      state: 'checking',
      label: COPY.apiStatus.checking,
      description: COPY.apiStatus.checkingDetail,
    };
  }

  if (data.status === 'ok') {
    return {
      state: 'reachable',
      label: COPY.apiStatus.reachable,
      description: COPY.apiStatus.reachableDetail,
    };
  }

  // The status string comes over the network: show it as (shortened) text only.
  return {
    state: 'unexpected',
    label: `${COPY.apiStatus.unexpected}: ${truncate(data.status, 40)}`,
    description: COPY.apiStatus.unexpectedDetail,
  };
}
