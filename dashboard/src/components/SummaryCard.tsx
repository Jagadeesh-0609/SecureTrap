import { useId } from 'react';

interface SummaryCardProps {
  label: string;
  /** Already formatted for display. */
  value: string;
  caption: string;
}

/** One headline figure with a caption stating exactly what it counts. */
export function SummaryCard({ label, value, caption }: SummaryCardProps) {
  const labelId = useId();
  return (
    <article className="summary-card" aria-labelledby={labelId}>
      <h3 id={labelId} className="summary-card__label">
        {label}
      </h3>
      <p className="summary-card__value">{value}</p>
      <p className="summary-card__caption">{caption}</p>
    </article>
  );
}
