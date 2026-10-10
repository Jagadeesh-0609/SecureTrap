import { useId, type ReactNode } from 'react';

export type StatePanelTone = 'info' | 'warning' | 'error';

interface StatePanelProps {
  tone: StatePanelTone;
  title: string;
  /** "alert" interrupts assistive technology; reserve it for failures. */
  role?: 'status' | 'alert';
  children?: ReactNode;
  actions?: ReactNode;
}

/** A titled message block used for the empty, unavailable and error states. */
export function StatePanel({ tone, title, role = 'status', children, actions }: StatePanelProps) {
  const titleId = useId();
  return (
    <section className={`state-panel state-panel--${tone}`} role={role} aria-labelledby={titleId}>
      <h2 id={titleId} className="state-panel__title">
        {title}
      </h2>
      {children ? <div className="state-panel__body">{children}</div> : null}
      {actions ? <div className="state-panel__actions">{actions}</div> : null}
    </section>
  );
}
