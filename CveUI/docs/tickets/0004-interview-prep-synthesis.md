# Ticket 0004 — Interview prep guide: synthesis (full-stack passing lanes, opening narrative, rapid-fire defaults, consistency pass)

**Blocked by:** 0002 and 0003

## Goal

Finishes the CveUI interview-prep guide by appending the cross-cutting synthesis and closing the document as a finished artifact.

## Scope

1. Theme: Full-stack camera passes (CveUI scope). Covered: the camelCase wire contract as the stack-wide agreement behind the stubbed-payload rationale of the test seam; error semantics as seen from the boundary (404 as "vendor/product pair not found" versus generic load failure, shaped by the not-found interceptor); the Keyword match semantics living API-side while the interface only carries the submitted Keyword; the read-only, no-server-state SPA topology ("URLs as the browsable source of truth"). Each subsection names where the .NET side would be asked about and gives the UI half cold without expanding out of scope.
2. The three-minute opening architecture narrative. Covered: a scripted walk-through of the Vulnerabilities page from inputs to computed parse guards to mode discrimination to idled resources to the clamp effect, touching signals, resources, routing, testing, and validation — the candidate's default opening answer to "describe this system."
3. Rapid-fire defaults. Covered: zoneless (no zone.js) and its consequences; RxJS versus signals split (interop at stream boundaries, signals inside components); defensive `localStorage` access patterns; deliberate current-major version bets and why they matter.
4. Glossary consistency read-through. Covered: a final pass ensuring guide phrasing stays aligned to the canonical vocabulary (**Vulnerabilities page**, **Keyword**, **Result set**, **Severity badge**, **Recent lookups**, **Recent lookup chip**, **Weaknesses page**), replacing any drifted phrasing the earlier tickets introduced.

## Deliverable expectations

- Ends with the "how to use this guide" closing promised by 0001's skeleton.
- Confirm-to-disk discipline: this ticket closes with the guide marked complete; no further tickets follow.
- Uses glossary vocabulary throughout.

## Notes

- Cannot start before both 0002 and 0003; synthesis is impossible without all themes on disk.

## Triage

- Label: `ready-for-agent`
