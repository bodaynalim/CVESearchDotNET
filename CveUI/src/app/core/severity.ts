/**
 * CVSS severity mapping, validated against the backend's severity-string
 * conventions (`CvssTwo.Severity` / `CvssThree.BaseSeverity`, imported from
 * NVD): CVSS3: None 0, Low < 4, Medium < 7, High < 9, Critical >= 9.
 * CVSS2 (no Critical tier): Low < 4, Medium < 7, High >= 7.
 * The API always ships a severity string, so the threshold functions are
 * the fallback for rows where the string is missing but the score is present.
 */

export type Severity = 'None' | 'Low' | 'Medium' | 'High' | 'Critical';

const LABELS = ['None', 'Low', 'Medium', 'High', 'Critical'] as const;

export function severityFromCvss3(score: number | undefined | null): Severity | null {
  if (score === undefined || score === null || Number.isNaN(score) || score < 0 || score > 10) {
    return null;
  }
  if (score <= 0) return 'None';
  if (score < 4) return 'Low';
  if (score < 7) return 'Medium';
  if (score < 9) return 'High';
  return 'Critical';
}

export function severityFromCvss2(score: number | undefined | null): Severity | null {
  if (score === undefined || score === null || Number.isNaN(score) || score < 0 || score > 10) {
    return null;
  }
  if (score <= 0) return 'None';
  if (score < 4) return 'Low';
  if (score < 7) return 'Medium';
  return 'High';
}

/**
 * Canonicalizes the API's severity strings ("HIGH" → "High");
 * unknown/missing/null/empty → null (badge will fall back to the score).
 */
export function canonicalSeverity(raw: string | undefined | null): Severity | null {
  if (!raw) return null;
  const normalized = raw.trim().toLowerCase();
  const match = LABELS.find(label => label.toLowerCase() === normalized);
  return match ?? null;
}

export function severityBadgeClass(severity: Severity | null): string {
  switch (severity) {
    case 'None':
      return 'bg-[var(--color-severity-none)]';
    case 'Low':
      return 'bg-[var(--color-severity-low)]';
    case 'Medium':
      return 'bg-[var(--color-severity-medium)]';
    case 'High':
      return 'bg-[var(--color-severity-high)]';
    case 'Critical':
      return 'bg-[var(--color-severity-critical)]';
    default:
      return 'bg-slate-400';
  }
}

/** Prefers the API's severity string; falls back to the score-threshold fn. */
export function resolveCvssSeverity(
  severityRaw: string | undefined | null,
  baseScore: number | undefined | null,
  version: 'v2' | 'v3',
): { severity: Severity | null; badgeClass: string } {
  const severity =
    canonicalSeverity(severityRaw) ??
    (version === 'v2' ? severityFromCvss2(baseScore) : severityFromCvss3(baseScore));
  return { severity, badgeClass: severityBadgeClass(severity) };
}
