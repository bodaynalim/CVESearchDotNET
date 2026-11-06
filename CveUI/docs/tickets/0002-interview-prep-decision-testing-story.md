# Ticket 0002 — Interview prep guide: decision & testing story (ADRs, single seam, zoneless discipline)

**Blocked by:** 0001

## Goal

Appends to the CveUI interview-prep guide the themes covering the candidate's differentiator material: why ADR culture is presentation-ready for interviews, why the single HTTP-boundary test seam works, and the zoneless test-discipline gotchas.

## Scope

1. Theme: ADR culture as interview communication. Covered:
   - ADR 0002 (URL-as-source-of-truth list contract): the rejected alternative (a separate search route for global browse), the one-screen/one-request-shape/one-URL-grammar argument, the root redirect making the Vulnerabilities page the default view, and the contract consequences (a submitted Keyword lands in the URL and resets to page 1; sort/size keep the page, only clamped when the Result set no longer covers it).
   - ADR 0001: the seam rationale (real components, real routing, only HTTP stubbed at the boundary; component-isolated tests and mock-service tests deliberately rejected).
   - ADR quality framing for interviewers: an ADR must name what was rejected and why.
2. Theme: The single-seam testing approach. Covered: `bootApp()` reusing production DI providers wholesale with the API base URL overridden and the testing backend swapped in; behavior assertions at the boundary ("this route issues this request and renders this table"); the tradeoff acknowledged without hedging.
3. Theme: Zoneless change-detection discipline in tests. Covered: `autoDetectChanges()`; the `settle()` one-macrotask yielding convention; the flush-before-`whenStable()` rule (failing to flush before `whenStable()` hangs the test while a request is in flight). Why this discipline belongs in interview prep: it demonstrates real zoneless system understanding rather than component-level trivia.

## Deliverable expectations

- Same per-theme structure as ticket 0001: what the code does (anchored file paths), why it is built that way, likely probes and strong answers.
- Uses glossary vocabulary: **Vulnerabilities page**, **Keyword**, **Result set**, **Weaknesses page**.
- Strictly additive to the guide built by 0001; must not restate or rewrite its predecessor's themes.

## Notes

- The ADR rejected-alternatives rationale is the candidate's best persuasive material; the section should model presenting decisions as narrative, not as bullet trivia.

## Triage

- Label: `ready-for-agent`
