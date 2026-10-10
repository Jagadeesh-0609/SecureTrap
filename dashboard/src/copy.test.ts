import { describe, expect, it } from 'vitest';

import { COPY } from './copy';

function allStrings(value: unknown): string[] {
  if (typeof value === 'string') {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.flatMap(allStrings);
  }
  if (typeof value === 'object' && value !== null) {
    return Object.values(value).flatMap(allStrings);
  }
  return [];
}

const strings = allStrings(COPY);

describe('COPY: semantics rules', () => {
  it('has strings to check', () => {
    expect(strings.length).toBeGreaterThan(30);
  });

  it('only mentions an attack to say an anomaly is not a confirmed one', () => {
    for (const text of strings.filter((s) => /attack/i.test(s))) {
      expect(text, text).toMatch(/\bnot (a )?confirmed attacks?\b/i);
    }
  });

  it('only mentions probability or confidence to say scores are neither', () => {
    for (const text of strings.filter((s) => /probabilit|confidence/i.test(s))) {
      expect(text, text).toMatch(/\bnot probabilities or confidence values\b/i);
    }
  });

  it('never claims the system is healthy, operational or all clear', () => {
    for (const text of strings) {
      expect(text, text).not.toMatch(/\b(healthy|operational|all clear|all systems|threat level|malicious)\b/i);
    }
  });

  it('scopes every headline figure to persisted/stored records', () => {
    for (const card of [COPY.cards.total, COPY.cards.anomalies, COPY.cards.normal, COPY.cards.rate]) {
      expect(card.label + ' ' + card.caption, card.label).toMatch(/persisted|stored/i);
    }
  });

  it('says normal_count is not the number of normal predictions', () => {
    expect(COPY.cards.normal.caption).toMatch(/not the number of normal predictions the model made/i);
  });

  it('says the anomaly share is not a share of all model predictions', () => {
    expect(COPY.cards.rate.caption).toMatch(/not the share of all model predictions/i);
  });

  it('puts the persisted-records scope in the always-visible banner text', () => {
    expect(COPY.scope.persisted).toMatch(/persisted in the SecureTrap alert store/i);
    expect(COPY.scope.persisted).toMatch(/not a summary of all traffic/i);
    expect(COPY.scope.persisted).toMatch(/not a count of every prediction the model has made/i);
  });

  it('states that a reachable /health does not verify the rest of the system', () => {
    expect(COPY.apiStatus.reachableDetail).toMatch(/does not verify the database, the detection service, or the honeypot/i);
  });

  it('admits the dashboard cannot see detector activity when the store is empty', () => {
    expect(COPY.states.empty.detail).toMatch(/no API endpoint reports detector activity/i);
  });
});
