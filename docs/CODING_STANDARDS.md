# Coding Standards — CVE Search API

These standards apply to the C#/.NET projects in this repository (Application, Domain, Infrastructure, Web, Tests). The CveUI project has its own set. They are the reference for code review ("hard" violations) alongside the judgement-call smell baseline in `AGENTS.md`.

## 1. Architecture principles

- **KISS.** Readable over clever. No premature abstractions, generic wrappers, or speculative interfaces.
- **DRY with a judgement exemption.** Extract repeated *business logic* into a dedicated service/helper. Do not couple otherwise-unrelated modules just to remove a few similar lines; small, deliberate duplication across the three Mongo service upsert paths is acceptable where shared extraction would distort ownership.
- **YAGNI.** Write for the immediate requirement: no unused parameters, extension points, or dead code paths. Delete dead branches when you touch a method that has them.
- **SOLID.**
  - *SRP*: one class, one reason to change; separate request parsing, validation, execution, and persistence.
  - *OCP*: extend via composition/strategy or new endpoints, not by growing monolithic `switch` statements.
  - *LISP*: substitutability holds — derived/related types must behave.
  - *ISP*: small focused interfaces (`ICveMongoService`, `ICweMongoService`), not God interfaces.
  - *DIP*: controllers depend on the Application-layer service interfaces (`ICveMongoService`), never on the Infrastructure implementations directly.

## 2. Layering (hard)

- **Web** = HTTP contract only. Controllers validate route parameters with attribute annotations (`[Range]`, `[Required]`, `[MinLength]`), call an Application service, map to a ViewModel, return `Ok`/`NotFound`/`BadRequest`. No Mongo, no AutoMapper profiles, no business decisions.
- **Application** = service interfaces + orchestration. The only place where cross-service workflows live.
- **Infrastructure** = Mongo services, HTTP/Vulnerabilities import helpers, config binding, AutoMapper profiles. Owns the `BaseMongoService<T>` plumbing.
- **Domain** (Common / Database / ViewModels) = plain models and records. No UI, HTTP, or driver logic where avoidable; ViewModels must not leak Mongo draft types.
- **ViewModel vs Mongo model**: the wire contract (ViewModel) and the persisted shape (Mongo model) are separate types, mapped explicitly. Never return a Mongo model directly from a controller.

## 3. REST contract conventions (hard)

- **Positional route segments**, matching the established style:
  - `cve/all/{count}/{page}/{descending}/{byPublished}`, `cve/search-count/{keyword}`
  - `cwe/all/{count}/{page}`, `cwe/search-count/{keyword}`
  - Count endpoints are separate routes from list endpoints (`.../count`, `.../search-count/{keyword}`) so one true count request serves all page turns of a result set.
- **Keyword semantics are fixed** (see ADR 0002): case-insensitive substring on a small field set (`CveId`+`Summary`, `CweId`+`Name`); a literal `CWE-` prefix on CWE searches is normalized away. Do not add ranking or multi-term logic ad hoc — amend the ADR first.
- camelCase **wire** casing is the contract with CveUI (see ADR 0001) — the C# property casing may differ; the wire wins.
- Every new endpoint documents its response type with `[ProducesResponseType(...)]` and XML `<summary>`/`<param>` comments.
- Writes to the database are import-only. Controllers must stay read-only.

## 4. C# language & syntax

- Modern C# preferred: file-scoped namespaces, records for immutable DTOs/ViewModels, switch expressions, pattern matching.
- Nullable reference types enforced: guard clauses > `?.` suppression > `!` (only with a comment justifying it).
- `async`/`await` end to end (hard): no `.Result`, `.Wait()`, `.GetAwaiter().GetResult()`. Pass `CancellationToken` to every I/O call, including Mongo driver calls.
- Lambdas in AutoMapper/query-trees cannot contain `?.` (expression trees) — stabilize with an explicit null check instead.

## 5. MongoDB access rules

- Injectable `IMongoCollection<T>`-rooted services; **Singleton lifetime is correct** (client is thread-safe).
- Filter, sort, skip/limit through the builder API; **no N+1** loops — batch fetches or aggregations instead.
- Prefer server-side filters (`CountDocumentsAsync`, positional/regex filters). For deliberately small collections, an in-memory sort+page over pre-filtered results is permitted **only with a comment sizing the collection** (cf. `CweMongoService.GetCweList`, ~1.5k docs). Count routes must use `CountDocumentsAsync`, never materialize documents.
- **Bulk upserts must never serialize `null` `_id`** (hard — bug of record): pin each replacement to its existing document's `_id`, or assign `ObjectId.GenerateNewId().ToString()` for genuinely new documents. Replacement documents with null `_id` hit the immutable-field error on update and duplicate-key E11000 on insert.
- Filters for keyword/listings come from the shared `KeywordFilterBuilder` (regex-escaped, case-insensitive `$or`) — do not hand-roll another regex builder.
- Async driver methods only, with cancellation tokens.

## 6. Error handling

- Expected conditions (validation, not-found) return status codes via controllers, not exceptions.
- Checker `NotFound` must include a human-meaningful message ("CWE-{id} is not found").
- Use the Result-style of a boolean/`null` return from the service layer for predictable misses; throw only for truly unexpected states.

## 7. Naming & layout

- PascalCase for classes, records, interfaces (prefixed `I`), methods, public members, and constants.
- camelCase for locals and parameters.
- Interfaces for DI-registered services live in Application; implementations in Infrastructure with matching names (`ICweMongoService` → `CweMongoService`).
- One class per file; file-scoped namespaces; regions (`#region Private`) allowed only for non-trivial helper grouping.
- Comments state the **why** (constraints, bug history in ADR references), never the **what**.

## 8. Testing

- xUnit + FluentAssertions + NSubstitute (project `Tests/Cve.Net.Search.Tests`).
- Test at a pure/judicious seam, not at Mongo-implementation detail:
  - pure logic (filter builders, mapper decisions) — direct unit tests;
  - import helpers — stub the HTTP seam (`StubHttpHandler`) and Mongo services.
- AAA + `Method_Scenario_Expected` naming.
- Keeping existing tests green is mandatory; the database is not a test fixture.
- **Documented bug fixes get a regression test where the logic is pure** (cf. `CveMappingTests` guarding the CVSS3/3.1 fallback).

## 9. Definitions of done

- Builds with zero errors; existing suites green.
- New public surface documented (XML comments) and followed to the REST conventions above.
- Linked GitHub ticket referenced in the commit message; review pass (two-axis or subagent template) before commit.
- Domain vocabulary/decisions made in passing belong in `GLOSSARY*.md` / `docs/adr/` immediately, not later.
