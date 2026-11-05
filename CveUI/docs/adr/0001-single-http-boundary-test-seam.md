# One HTTP-boundary test seam for all UI behavior tests

CveUI tests real components with real routing through the whole app shell, stubbing only HTTP with Angular's `HttpTestingController` (the `bootApp()` helper). There is exactly one seam: the network boundary. Component-isolated tests and mock-service tests were deliberately rejected.

Rationale: with URL-as-source-of-truth routing, runtime semantics live in the integration of router → component inputs → resource scheduling, and isolated component tests repeatedly drifted from real behavior (query-param binding, zoneless scheduling, resource error semantics). One seam means less duplication, tests survive refactors, and behavior — "does this route issue this request and render this table" — is what gets asserted, never internals.

Consequence: a shared `settle()` macrotask helper and the flush-before-`whenStable()` discipline are part of the seam's contract; new page tests should reuse `bootApp()` rather than spin new seams. Cross-referenced with the API-side ADR 0001 for why the stubbed payloads are camelCase.
