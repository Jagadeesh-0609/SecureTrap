import { Link } from 'react-router-dom';

import { StatePanel } from '../components/StatePanel';
import { COPY } from '../copy';

export function NotFoundPage() {
  return (
    <StatePanel tone="info" title={COPY.states.notFound.title}>
      <p>{COPY.states.notFound.body}</p>
      <p>
        <Link to="/">{COPY.states.notFound.back}</Link>
      </p>
    </StatePanel>
  );
}
