import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { makeAllFlaggedSummary, makeSummary } from '../test/fixtures';
import { SummaryCards } from './SummaryCards';

function card(name: string) {
  return screen.getByRole('article', { name });
}

describe('SummaryCards', () => {
  it('shows the four persisted-record figures with their values', () => {
    render(<SummaryCards summary={makeSummary()} />);

    expect(within(card('Persisted alerts')).getByText('5')).toBeInTheDocument();
    expect(within(card('Persisted anomalies')).getByText('2')).toBeInTheDocument();
    expect(within(card('Persisted non-anomalous records')).getByText('3')).toBeInTheDocument();
    expect(within(card('Anomaly share of persisted records')).getByText('40%')).toBeInTheDocument();
  });

  it('shows exactly four cards', () => {
    render(<SummaryCards summary={makeSummary()} />);

    expect(screen.getAllByRole('article')).toHaveLength(4);
  });

  it('formats large counts with grouping', () => {
    render(
      <SummaryCards
        summary={makeSummary({ total_alerts: 1234567, anomaly_count: 1000000, normal_count: 234567 })}
      />,
    );

    expect(within(card('Persisted alerts')).getByText('1,234,567')).toBeInTheDocument();
    expect(within(card('Persisted anomalies')).getByText('1,000,000')).toBeInTheDocument();
  });

  it('formats the rate as a percentage of persisted records', () => {
    render(<SummaryCards summary={makeSummary({ anomaly_rate: 0.3333 })} />);

    expect(
      within(card('Anomaly share of persisted records')).getByText('33.3%'),
    ).toBeInTheDocument();
  });

  it('says on the cards what each figure is NOT', () => {
    render(<SummaryCards summary={makeSummary()} />);

    expect(
      within(card('Persisted non-anomalous records')).getByText(
        /not the number of normal predictions the model made/i,
      ),
    ).toBeInTheDocument();
    expect(
      within(card('Anomaly share of persisted records')).getByText(
        /not the share of all model predictions/i,
      ),
    ).toBeInTheDocument();
    expect(
      within(card('Persisted anomalies')).getByText(/not confirmed attacks/i),
    ).toBeInTheDocument();
  });

  it('explains the 100% share when every persisted record is flagged', () => {
    render(<SummaryCards summary={makeAllFlaggedSummary(3)} />);

    expect(within(card('Persisted non-anomalous records')).getByText('0')).toBeInTheDocument();
    expect(within(card('Anomaly share of persisted records')).getByText('100%')).toBeInTheDocument();
    expect(screen.getByRole('note')).toHaveTextContent(/says nothing about how many normal events/i);
  });

  it('does not show that explanation when non-anomalous records exist', () => {
    render(<SummaryCards summary={makeSummary()} />);

    expect(screen.queryByRole('note')).not.toBeInTheDocument();
  });
});
