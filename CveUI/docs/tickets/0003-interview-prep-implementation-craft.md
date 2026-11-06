# Ticket 0003 — Interview prep guide: implementation-craft themes (severity logic, router patterns, theme tokens)

**Blocked by:** 0001

## Goal

Appends to the CveUI interview-prep guide the remaining code-grounded craft themes: pure-function business logic, router and composition patterns, and Tailwind theme tokens.

## Scope

1. Theme: CVSS severity mapping as pure business logic. Covered: the v2/v3 threshold functions (v2 has no Critical tier), canonicalization of the API's severity strings with unknown/missing falling to null, the fallback chain (severity string from the API, then score-threshold function, then the "Not scored" chip), why the pure functions justify standalone unit specs despite the integration-first testing stance of the seam (scope per ticket 0001).
2. Theme: Router and composition patterns. Covered: standalone components with inline templates for colocation; built-in control flow (`@if ... as`, `@for` with identity-based `track` on CVE ID, never index); query-param-to-`input()` binding via `withComponentInputBinding` and how a marker route's param conflicts are avoided; shell composition of router events into a section-title signal via `toSignal` interop at the boundary (RxJS at event streams only, signals inside components). Note the Keyword-match semantics live API-side; the interface only carries the submitted Keyword.
3. Theme: Tailwind 4 `@theme` design tokens. Covered: the light content + dark indigo sidebar design language; tokens declared once (`--color-nav-*` sidebar palette, `--color-brand`, severity palette, page background, card border, panel accent); consumption via `var()` arbitrary values in templates and via the severity-badge class mapping function being the single place a severity *name* maps to a color; base typography via `@apply`.

## Deliverable expectations

- Same per-theme structure as 0001: what the code does (anchored file paths), why, probes and strong answers.
- Uses glossary vocabulary: **Vulnerabilities page**, **Keyword**, **Severity badge**, **Result set**.
- Strictly additive; no restatement of 0001 themes.

## Notes

- This ticket starts the moment 0001 lands, in parallel with 0002; both append distinct sections so ordering does not matter, but section headers must stay consistent.

## Triage

- Label: `ready-for-agent`
