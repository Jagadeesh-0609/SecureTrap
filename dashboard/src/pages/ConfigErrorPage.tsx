import { StatePanel } from '../components/StatePanel';
import { COPY } from '../copy';

/** Shown instead of the app when VITE_API_BASE_URL is malformed. */
export function ConfigErrorPage({ reason }: { reason: string }) {
  return (
    <main className="config-error">
      <StatePanel tone="error" role="alert" title={COPY.states.config.title}>
        <p>
          <code>{COPY.states.config.lead}</code> {reason}
        </p>
        <p>{COPY.states.config.fix}</p>
      </StatePanel>
    </main>
  );
}
