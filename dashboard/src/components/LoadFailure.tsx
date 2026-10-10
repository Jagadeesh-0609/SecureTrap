import { ApiError } from '../api/client';
import { apiConfig, describeApiBase } from '../config';
import { COPY } from '../copy';
import { describeError, isUnavailableError } from '../pages/overviewState';
import { StatePanel } from './StatePanel';

interface LoadFailureProps {
  error: Error;
  onRetry: () => void;
}

/**
 * Explains why the summary could not be loaded, distinguishing "the API
 * cannot be reached" from "the API answered, but badly".
 */
export function LoadFailure({ error, onRetry }: LoadFailureProps) {
  const retry = (
    <button type="button" className="button" onClick={onRetry}>
      {COPY.states.retry}
    </button>
  );

  if (isUnavailableError(error)) {
    const { title, body, hints, configured } = COPY.states.unavailable;
    return (
      <StatePanel tone="warning" role="alert" title={title} actions={retry}>
        <p>{body}</p>
        <ul>
          {hints.map((hint) => (
            <li key={hint}>{hint}</li>
          ))}
        </ul>
        <p className="state-panel__meta">
          {configured} <code>{apiConfig.ok ? describeApiBase(apiConfig.baseUrl) : 'unknown'}</code>
        </p>
      </StatePanel>
    );
  }

  if (error instanceof ApiError && error.kind === 'invalid') {
    const { title, body } = COPY.states.invalidResponse;
    return (
      <StatePanel tone="error" role="alert" title={title} actions={retry}>
        <p>{body}</p>
        <p className="state-panel__meta">{describeError(error)}</p>
      </StatePanel>
    );
  }

  const { title, body } = COPY.states.httpError;
  return (
    <StatePanel tone="error" role="alert" title={title} actions={retry}>
      <p>{body}</p>
      <p className="state-panel__meta">{describeError(error)}</p>
    </StatePanel>
  );
}
