# T02 — Golden-dataset для keyword search

**Blocked by:** — (стартує одразу)

## Мета

Семантика keyword search (ADR-0002: case-insensitive substring matching) закріплена
явними golden-прикладами, а не лише прозою ADR.

## Що робить (vertical slice)

1. Golden-фікстура (~20–30 записів CVE) у тест-проєкті: вхідні дані + очікувані результати.
2. Юніт-тести на KeywordFilterBuilder поверх фікстури.
3. Інтеграційний тест на репозиторії/пошуку поверх Mongo (testcontainer або наявний
   інтеграційний підхід кодбази) — той самий dataset.
4. Терміни з GLOSSARY.md; нові терміни (якщо з'являться) — одразу в глосарій.

## Кейси, які має покрити dataset

- Точний збіг; регістр (ADR-0002 — нечутливість); підстрінг посередині терміна
- Спецсимволи та розділювачі (дефіс, крапка, CVE-формат id)
- Порожній запит / null-запит (очікувана поведінка — за наявним контрактом)
- Кілька keyword'ів одночасно
- Записи, що НЕ мають зматчитись (негативні приклади)

## Verifiable outcome

- `dotnet test` запускає нові golden-тести; навмисна зміна семантики фільтра падає з
  читабельним diff-звітом, який приклад порушено.

## Acceptance criteria

- [ ] Фікстура покриває всі перелічені кейси, включно з негативними
- [ ] Тести лише на зовнішню поведінку (результат пошуку), не на внутрішні деталі білдера
- [ ] Фікстури — явні очікувані результати, рев'ючені людиною (не згенеровані з поточного коду)
- [ ] Юніт та інтеграційний рівні використовують той самий dataset

## Prior art

KeywordFilterBuilderTests (стиль юніт-тестів), Cve.Net.Search.Tests загалом.

## Out of scope

- Зміна семантики пошуку (тільки через ADR-0002)
- CI job `evals` (T07) та живий API (T11)

## Implementation notes

- Shipped as unit-level golden tests only: `KeywordGoldenDataset.cs` (fixture) +
  `KeywordGoldenDatasetTests.cs` in `Tests/Cve.Net.Search.Tests`.
- **Integration layer deferred**: the codebase has no Mongo-free integration seam for the
  search repository. `CveMongoService`/`CweMongoService` take a live `IMongoCollection<T>`
  (constructor-injected via `BaseMongoService<T>`); the existing
  `VulnerabilitiesJsonHelperInitialImportTests` seam stubs Mongo *services* with NSubstitute,
  which verifies import orchestration but cannot execute real filters against a dataset.
  Standing up MongoDB (testcontainers/ephemeral server) is a separate change. Until then the
  golden cases run through the production `KeywordFilterBuilder` filter, rendered to Bson and
  evaluated against the fixture records with the rendered per-field regexes — the observable
  substring-matching behaviour, so the same dataset and expectations are what an integration
  test will consume when the seam exists.
- Empty-keyword contract pinned: the CVE search routes reject empty/null keywords via
  `[Required][MinLength(1)]`; the empty string filter itself matches everything (substring
  semantics); `null` throws `ArgumentNullException` (CWE's nullable-keyword path bypasses the
  builder entirely with `Filter.Empty`).
- Dataset: 24 CVE records, 22 positive cases, 6 negative cases. Expected results are
  hand-written; a fixture-integrity test additionally requires every record to be reachable
  by at least one golden case and ids to be unique.
