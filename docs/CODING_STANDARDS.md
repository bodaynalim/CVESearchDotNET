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

- Modern C# preferred: file-scoped namespaces, records for immutable DTOs/ViewModels, switch expressions, relational pattern matching instead of nested `if-else` cascades.
- Primary constructors are allowed for DI-injected classes where they stay readable.
- Nullable reference types enforced: guard clauses > `?.` suppression > `!` (only with a comment justifying it).
- `async`/`await` end to end (hard): no `.Result`, `.Wait()`, `.GetAwaiter().GetResult()`. Pass `CancellationToken` to every I/O call, including Mongo driver calls.
- `ValueTask`/`ValueTask<T>` only on hot paths that usually complete synchronously; default to `Task`.

## 4a. Style rules (hard)

- Naming: PascalCase classes/records/interfaces (`I` prefix)/methods/public members/constants; camelCase locals and parameters; `_camelCase` leading underscore for private fields.
- Guard clauses and early returns; maximum nesting depth 2–3 levels.
- Methods short and focused (ideally under 20–30 lines); one class per file; file-scoped namespaces.

## 5. Dependency Injection (hard)

- Standard Microsoft DI only (`IServiceCollection`), wired in `Web/Cve.Net.Search.Web/Program.cs`.
- `Singleton` for stateless, thread-safe services — **all Mongo services and `MongoClient`-backed types are registered Singleton** (the client is thread-safe; per-request construction is wasted work).
- `Scoped`/`Transient` only where per-request state genuinely exists (this codebase currently has none of the data-store kind; don't add one reflexively).

## 5a. Resource management

- Every `IDisposable`/`IAsyncDisposable` (streams, HTTP responses, Mongo clients in scripts) via `using`/`await using` or DI-managed lifetimes; the import helpers dispose download/extract streams explicitly.
- `IHttpClientFactory`-produced clients are used per-operation; never hold long-lived `HttpClient` instances of your own.

## 6. MongoDB access rules

- Injectable `IMongoCollection<T>`-rooted services; **Singleton lifetime is correct** (client is thread-safe).
- Filter, sort, skip/limit through the builder API; **no N+1** loops — batch fetches or aggregations instead.
- Indexes are created and maintained in the services' `EnsureIndexesAsync` (`IndexBootstrapper` runs them at startup) — when you add a queryable field to a hot filter, add the matching index there.
- Prefer server-side filters (`CountDocumentsAsync`, positional/regex filters). For deliberately small collections, an in-memory sort+page over pre-filtered results is permitted **only with a comment sizing the collection** (cf. `CweMongoService.GetCweList`, ~1.5k docs). Count routes must use `CountDocumentsAsync`, never materialize documents.
- **Bulk upserts must never serialize `null` `_id`** (hard — see `docs/adr/0003-bulk-upserts-carry-concrete-ids.md` for the full contract): pin each replacement to its existing document's `_id`, or assign `ObjectId.GenerateNewId().ToString()` for genuinely new documents.
- Filters for keyword/listings come from the shared `KeywordFilterBuilder` (regex-escaped, case-insensitive `$or`) — do not hand-roll another regex builder.
- Async driver methods only, with cancellation tokens; projection (`.Project<T>()`) whenever only a subset of fields is needed.

## 7. Error handling

- Expected conditions (validation, not-found) return status codes via controllers, not exceptions; the repo does **not** use a Result library or RFC 7807 Problem Details middleware.
- `NotFound` responses include a human-meaningful message ("CWE-{id} is not found"); 400s surface route-validation failures.
- Return `null`/boolean/plain objects from the service layer for predictable misses; throw only for truly unexpected states.
- Lambda expressions feeding AutoMapper/query trees cannot contain `?.` (expression trees) — use an explicit null check instead (cf. the CVSS fallback in `VulnerabilitiesProfile`).

## 8. Naming & layout

- PascalCase for classes, records, interfaces (prefixed `I`), methods, public members, and constants.
- camelCase for locals and parameters.
- `_camelCase` leading underscore for private fields.
- Interfaces for DI-registered services live in Application; implementations in Infrastructure with matching names (`ICweMongoService` → `CweMongoService`).
- One class per file; file-scoped namespaces; regions (`#region Private`) allowed only for non-trivial helper grouping.
- Comments state the **why** (constraints, bug history, ADR references), never the **what**.

## 9. Testing

- xUnit + FluentAssertions + NSubstitute (project `Tests/Cve.Net.Search.Tests`) — no NUnit, no Moq.
- Test at a pure/judicious seam, not at Mongo-implementation detail:
  - pure logic (filter builders, mapper decisions) — direct unit tests;
  - import helpers — stub the HTTP seam (`StubHttpHandler`) and Mongo services.
- AAA + `Type_Scenario_Expected` naming (e.g. `Cve_WithOnlyCvss31_FallsBackToCvss31InViewModel`).
- Keeping existing tests green is mandatory; the database is not a test fixture.
- **Documented bug fixes get a regression test where the logic is pure** (cf. `CveMappingTests` guarding the CVSS3/3.1 fallback).

## 10. Definition of done

- Builds with zero errors; existing suites green.
- New public surface documented (XML comments) and following the REST conventions above.
- Linked GitHub ticket referenced in the commit message; review pass (two-axis or subagent template) before commit.
- Domain vocabulary/decisions made in passing belong in `GLOSSARY*.md` / `docs/adr/` immediately, not later.
