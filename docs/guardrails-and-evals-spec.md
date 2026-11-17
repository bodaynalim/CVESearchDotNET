# Spec: Guardrails & Evals для Cve.Net.Search

> Статус: spec, не опублікований у трекер (за рішенням автора).
> Джерело: [guardrails-and-evals-plan.md](guardrails-and-evals-plan.md).
> Термінологія — [GLOSSARY.md](GLOSSARY.md); ADR-0001 (camelCase) та ADR-0002 (keyword search semantics) обов'язкові до дотримання.

## Problem Statement

Команда та AI-агенти працюють над проєктом без механізованих бар'єрів якості. Єдиний gate — CI, який ловить проблеми лише після push; тестовий набір не фіксує якість пошуку і мапінгу даних на рівні очікуваних результатів ("golden" поведінки), а агент має змогу виконувати деструктивні дії та змінювати авторитетні документи без явного рішення людини. Регресії wire-контракту (ADR-0001), семантики keyword search (ADR-0002) або шарингу проєктів виявляються пізно й вручну.

## Solution

Додати три рівні захисту: (1) guardrails для AI-агента — permissions та пре-коміт preflight у репозиторії; (2) engineering guardrails — warnings-as-errors, повний build у CI, покриття, architecture та contract-тести; (3) evals — golden-dataset тести keyword search, golden-фікстури CVE-мапінгу, contract evals живого API та data-quality перевірки delta jobs, виділені в окремий CI job.

## User Stories

1. As a maintainer, I want compiler warnings to fail the build, so that low-quality code cannot merge unnoticed.
2. As a maintainer, I want the whole solution built in CI with warnings-as-errors, so that a broken non-test project is caught before merge.
3. As a maintainer, I want a coverage threshold in CI, so that test coverage cannot silently decay.
4. As a maintainer, I want architecture tests enforcing layer boundaries, so that the layering rules in CODING_STANDARDS are mechanized.
5. As a maintainer, I want REST contract snapshot tests, so that the camelCase wire contract (ADR-0001) cannot regress.
6. As a maintainer, I want a golden dataset for keyword search, so that search semantics (ADR-0002) are pinned against documented examples.
7. As a maintainer, I want golden fixtures for CVE JSON mapping, so that real-world NVD payloads map to the domain model exactly as decided.
8. As a maintainer, I want contract evals against a running API, so that wire-contract regressions are caught end-to-end, not only at serializer level.
9. As a maintainer, I want data-quality checks for the delta jobs, so that regenerated MongoDB state meets structural invariants without treating DB state as a fixture.
10. As a maintainer, I want evals in a separate CI job, so that eval failures are visible independently of unit test failures.
11. As an AI agent, I want deny rules for destructive shell commands, so that I cannot accidentally destroy local data or publish artifacts.
12. As an AI agent, I want ask-level permissions on authoritative docs, so that changing recorded decisions is always a human decision.
13. As an AI agent, I want a preflight script, so that I can validate my changes before attempting a commit.
14. As a human reviewer, I want preflight to enforce ticket references in commit messages, so that traceability (AGENTS.md §4) is automatic.
15. As a human reviewer, I want a mechanical review checklist for the review agent, so that two-axis review (standards + spec) is consistently applied.
16. As a developer working on the search feature, I want documented golden examples of keyword behavior, so that I can see the intended semantics without reading ADR prose.
17. As a developer changing mapping code, I want a real NVD fixture with expected output, so that I know immediately which mapping rule I broke.
18. As a developer running delta jobs locally, I want invariant checks over job output fixtures, so that I can validate jobs without a live database.

## Implementation Decisions

- **Warnings-as-errors**: рішення на рівні solution — всі проекти наслідують спільні налаштування; включає nullable reference types та Roslyn analysis level "latest-recommended". Це рішення має бути закріплене в CODING_STANDARDS.md.
- **CI job `api`**: розширюється повним build solution (з `-warnaserror`) перед тестами; після тестів — збір покриття з порогом (стартово 60%).
- **Architecture tests**: окремий тестовий модуль, що перевіряє відсутність залежностей Domain → Infrastructure/Web та Application → Infrastructure/Web (референсні обмеження, без виконання коду).
- **Contract-тести**: серіалізаційні снепшоти відповідей контролерів — закріплюють camelCase (ADR-0001) та стиль роутів.
- **Golden-dataset keyword search**: фікстура з ~20–30 записів та очікуваних результатів; семантика — case-insensitive substring (ADR-0002), включно з крайніми випадками (порожній запит, спецсимволи, регістр).
- **Golden CVE mapping fixture**: один реальний NVD payload як fixture з очікуваним доменним об'єктом; розширення існуючих mapping-тестів.
- **API contract evals**: скрипт, що піднімає API та звіряє відповіді endpoint'ів з JSON-схемами, які зберігаються у docs; запускається локально та (згодом) окремим CI job `evals`.
- **Delta job data-quality checks**: інваріанти над фікстурами job-виходу (непорожні id, дедупікація, монотонність дат модифікації, очікуваний розмір дельт); MongoDB state не використовується як fixture (AGENTS.md §2).
- **Agent permissions**: до `opencode.json` додаються `permission.edit` правила (авторитетні docs → ask) та deny для `rm -rf`, database drop, publish/push артефактів; `mongo*` → ask.
- **Preflight**: скрипт build + тести + doc-link check + перевірка формату commit message (наявність номера тікету); правило його запуску перед commit фіксується в AGENTS.md.
- **Review checklist**: список обов'язкових чеків (ADR не порушено, camelCase contract, Mongo rules) додається до конфігурації review-агента.

## Testing Decisions

- Тести перевіряють зовнішню поведінку (JSON wire, результати пошуку, вихід job'ів), а не внутрішню реалізацію; golden-фікстури — явні очікувані результати, а не знімки, згенеровані з поточного коду без рев'ю.
- Тестуються: шаринг проєктів (architecture tests), серіалізація контролерів, keyword search, CVE мапінг, delta job інваріанти.
- Prior art у кодбазі: тест-стиль `Tests/Cve.Net.Search.Tests` (xUnit, існуючі `KeywordFilterBuilderTests`, `CveMappingTests`, `VulnerabilitiesJsonHelperInitialImportTests` — розширюються, а не замінюються).
- Evals живуть в окремому CI job `evals`, щоб падіння eval-ів не зливалося з юніт-тестами.

## Seams (пропозиція — потребує підтвердження)

Три наявні шви, нових швів не вводиться:

1. **KeywordFilterBuilder + Mongo інтеграційний шар** — golden-dataset подається у наявний шов фільтра пошуку (юніт) та інтеграційно в репозиторій (testcontainer).
2. **Serializer/контролери** — contract-снепшоти існуючого wire-шва без нових абстракцій.
3. **Процесний шов**: preflight та api-eval — скрипти як зовнішні guards, без тестових подвійних всередині продукту.

## Out of Scope

- LLM-функціонал у продукті та LLM-evals (такого коду немає).
- Заміна або переписування наявних тестів; нова інфраструктура трекера чи нові інструменти поза NuGet/npm, вже узгодженими стандартами.
- Зміна записаних ADR-рішень (спек фіксує їх, не змінює).
- Автоматичний публіш спеки або результатів evals у зовнішні системи.

## Further Notes

- Пріоритет впровадження (перший PR): warnings-as-errors → повний build у CI → golden-dataset keyword search; далі deny-правила агента та preflight.
- Після прийняття пункти warnings-as-errors та contract-тестів закріплюються в CODING_STANDARDS.md; зміна семантики пошуку — тільки через ADR-0002.
- Трекер/лейбли для публікації не налаштовані; спек зберігається у docs до рішення про трекер.
