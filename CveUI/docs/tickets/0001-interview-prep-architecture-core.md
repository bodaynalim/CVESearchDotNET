# Ticket 0001 — Interview prep guide: architecture core (skeleton + signals + httpResource + page clamp)

**Blocked by:** none

## Goal

Begins the CveUI interview-prep guide (`CveUI/docs/interview-prep.md`) with its skeleton plus the three strongest code-grounded themes. The ticket is complete when the guide exists as a standalone-readable document that can be demoed to a candidate preparing for a full-stack interview.

## Scope

1. Guide skeleton:
   - Title stating it is a CveUI interview-prep theme guide.
   - An "how to use this guide" outro note confirming the doc is additive (later tickets append themes).
   - Version anchors table: Angular 22, TypeScript 6, Vitest + jsdom, Tailwind 4, zoneless, npm 11 pinned.
2. Theme: Signals-first state ownership. Covered: URL-as-source-of-truth for all listing state (vendor/product scope, Keyword, page, count, sort, direction) bound as component inputs via `withComponentInputBinding`; derived state as pure `computed()` parse functions guarding out-of-set and out-of-range URL values; `Recent lookups` held in a signal seeded from `localStorage` with normalization, dedup, cap at five, and try/catch degradation when storage is unavailable. States the topology decision plainly: URL for anything shareable, signals for derived/ephemeral state, browser-local storage for `Recent lookups`, no global store.
3. Theme: `httpResource` data layer. Covered: the `createResource` wrapper running `httpResource` inside the caller's injection context (NG0203); the Cve API facade (scoped search, global/keyword list, counts, detail, last published/modified) with URL path-segment encoding; the discriminated request unions; the request-getter-returns-undefined idling pattern that guarantees exactly one listing and one count request is ever live.
4. Theme: The effect + `untracked` page clamp. Covered: the clamp-back-into-range effect when a re-sort or smaller page size shrinks the Result set below the current page; why the effect reads `total` as its dependency and uses `untracked` for the page descriptors to avoid a URL write/read ping-pong; the "reaction, not derivation" vocabulary.

## Deliverable expectations

- Every theme includes: what the code does (anchored to file paths), why it is built that way, likely interviewer probes with strong answers grounded in ADR rationale.
- Vocabulary must use the CveUI glossary: **Vulnerabilities page**, **Keyword** (never "live search"/"filter"), **Result set**, **Severity badge**, **Recent lookups**, **Recent lookup chip**.

## Notes

- This ticket opens the guide; tickets 0002 and 0003 append further theme sections before ticket 0004 synthesizes closing material. The outro note must acknowledge the incoming sections so the intermediate state of the doc is intentional, not broken.

## Triage

- Label: `ready-for-agent`
