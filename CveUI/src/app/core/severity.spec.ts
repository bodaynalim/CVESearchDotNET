import {
  canonicalSeverity,
  resolveCvssSeverity,
  severityBadgeClass,
  severityFromCvss2,
  severityFromCvss3,
} from './severity';

describe('severityFromCvss3 (NVD base-severity thresholds)', () => {
  it.each([
    [0, 'None'],
    [0.1, 'Low'],
    [3.9, 'Low'],
    [4.0, 'Medium'],
    [6.9, 'Medium'],
    [7.0, 'High'],
    [8.9, 'High'],
    [9.0, 'Critical'],
    [10, 'Critical'],
  ] as const)('maps score %s to %s', (score, expected) => {
    expect(severityFromCvss3(score)).toBe(expected);
  });

  it.each([[-0.1], [10.1], [Number.NaN]])('rejects out-of-domain score %s', (score) => {
    expect(severityFromCvss3(score)).toBeNull();
  });

  it('rejects missing scores', () => {
    expect(severityFromCvss3(undefined)).toBeNull();
    expect(severityFromCvss3(null)).toBeNull();
  });
});

describe('severityFromCvss2 (no Critical tier)', () => {
  it.each([
    [0, 'None'],
    [3.9, 'Low'],
    [4.0, 'Medium'],
    [6.9, 'Medium'],
    [7.0, 'High'],
    [10, 'High'], // CVSS2 tops out at High
  ] as const)('maps score %s to %s', (score, expected) => {
    expect(severityFromCvss2(score)).toBe(expected);
  });
});

describe('canonicalSeverity (API severity strings)', () => {
  it('normalizes uppercase and mixed casing to canonical labels', () => {
    expect(canonicalSeverity('HIGH')).toBe('High');
    expect(canonicalSeverity('Critical')).toBe('Critical');
    expect(canonicalSeverity(' medium ')).toBe('Medium');
  });

  it('returns null for unknown or empty strings', () => {
    expect(canonicalSeverity('MODERATE')).toBeNull();
    expect(canonicalSeverity('')).toBeNull();
    expect(canonicalSeverity(undefined)).toBeNull();
    expect(canonicalSeverity(null)).toBeNull();
  });
});

describe('resolveCvssSeverity (string preferred, thresholds as fallback)', () => {
  it('uses the API severity string when present, even without a score', () => {
    const resolved = resolveCvssSeverity('HIGH', undefined, 'v2');
    expect(resolved.severity).toBe('High');
  });

  it('falls back to the version-specific thresholds when the string is missing', () => {
    // Same score, different generations: CVSS2 has no Critical tier.
    expect(resolveCvssSeverity(undefined, 9.8, 'v2').severity).toBe('High');
    expect(resolveCvssSeverity(undefined, 9.8, 'v3').severity).toBe('Critical');
  });

  it('yields badge classes per severity and an unclassified default', () => {
    expect(severityBadgeClass('Critical')).toContain('--color-severity-critical');
    expect(severityBadgeClass('Low')).toContain('--color-severity-low');
    expect(severityBadgeClass(null)).toBe('bg-slate-400');
  });
});
