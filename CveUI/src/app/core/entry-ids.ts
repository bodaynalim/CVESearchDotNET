/**
 * Shared numeric-id helpers for CWE/CAPEC entry pages.
 * The REST endpoints (`/cwe/{id}`, `/capec/{id}`) take bare numeric ids,
 * e.g. 79 or 1001. CVE responses reference weaknesses as "CWE-<n>".
 */

/** "79" → 79; anything non-numeric → null (caller renders it unlinked). */
export function parseNumericId(value: string): number | null {
  const match = /^(\d+)$/.exec(value.trim());
  return match ? Number.parseInt(match[1], 10) : null;
}

/** "CWE-79" or bare "79" → "79"; other markers (e.g. "NVD-CWE-noinfo") → null. */
export function cweRouteParam(cweEntry: string): string | null {
  const match = /^(?:CWE-)?(\d+)$/i.exec(cweEntry.trim());
  return match ? match[1] : null;
}

/** CAPEC references in payloads are bare numeric ids (verified live). */
export function capecRouteParam(value: string): number | null {
  return parseNumericId(value);
}
