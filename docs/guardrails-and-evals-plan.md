# Guardrails & Evals — план впровадження

> Статус: пропозиція (не ADR, не стандарт). Створено 2026-11-17.
> Після погодження окремі пункти (2.1, 2.4) мають бути закріплені в
> [CODING_STANDARDS.md](CODING_STANDARDS.md) або власним ADR, а не жити лише тут.

## Контекст (стан на сьогодні)

- CI: `.github/workflows/ci.yml` — jobs `api` (dotnet test), `cveui` (typecheck, tests, build), `docs` (link check). Немає: покриття, аналізаторів, `warnaserror`, lint.
- Тести: `Tests/Cve.Net.Search.Tests` — 4 файли (мапінг, keyword-фільтр, Hangfire options, initial import).
- Агент: `opencode.json` (permission: bash `*` → ask, `git commit/push` → deny), `.opencode/skills/*`, agent `review.md`.
- LLM-функцій у коді продукту немає.

---

## 1. Guardrails для AI-агента

| #  | Що                                              | Куди                                                        | Навіщо |
|----|--------------------------------------------------|-------------------------------------------------------------|--------|
| 1.1| Заборона редагувати "авторитетні" файли          | `opencode.json` → `permission.edit`: `docs/CODING_STANDARDS.md`, `docs/adr/*`, `docs/GLOSSARY.md` → `ask`; `AGENTS.md` → `ask` | Зміна записаного рішення — рішення людини (правило з AGENTS.md про ADR) |
| 1.2| Deny на деструктивні shell-команди               | `opencode.json`: `rm -rf *`, `dotnet ef database drop*`, `npm publish*`, `dotnet nuget push*` → `deny`; `docker * down*`, `mongo*` → `ask` | Зараз заблоковано лише `git commit/push` |
| 1.3| Mongo-стан не як fixture                         | Правило в `AGENTS.md` §2 + deny/ask на `mongo*` у `opencode.json` | Delta jobs регенерують дані — БД не фікстура (уже сформульовано, механізувати) |
| 1.4| Обов'язковий пре-коміт gate                      | `scripts/preflight.ps1` (build + tests + doc-link check) + правило в `AGENTS.md`: запуск перед `git commit` | Ловити обриви до push, а не в CI |
| 1.5| Commit-формат                                    | Перевірка в preflight: message містить номер тікету (§4 AGENTS.md) | Механізувати текстову умову |
| 1.6| Чеклист review-агента                            | `.opencode/agent/review.md`: обов'язкові чеки — ADR не порушено, camelCase contract (ADR-0001), Mongo rules | Формалізувати two-axis review |

## 2. Engineering guardrails проєкту

| #  | Що                          | Як |
|----|------------------------------|----|
| 2.1| Warnings-as-errors          | `Directory.Build.props`: `TreatWarningsAsErrors=true`, `Nullable=enable`, `AnalysisLevel=latest-recommended` |
| 2.2| Покриття в CI               | `dotnet test --collect:"XPlat Code Coverage"` + threshold (стартово ~60%) |
| 2.3| Architecture tests          | Тести, що `Domain`/`Application` не залежать від `Infrastructure`/`Web` (NetArchTest.Rules або reflection) — закріплює шаринг з CODING_STANDARDS |
| 2.4| Contract-тести REST         | Снепшот-тести серіалізації контролерів: JSON у camelCase (ADR-0001), стиль роутів |
| 2.5| CI: build усього solution   | `dotnet build Cve.Net.Search.sln -warnaserror` окремим step у job `api` |
| 2.6| UI: lint у CI               | `npm run lint` у job `cveui` (за наявності скрипта) |

## 3. Evals якості даних і пошуку

| #  | Що                                  | Як |
|----|--------------------------------------|----|
| 3.1| Golden-dataset для keyword search   | Фікстура ~20–30 CVE-записів + очікувані результати: точний збіг, регістр (ADR-0002), підстрінг, спецсимволи, порожній запит. Юніт-рівень на `KeywordFilterBuilder` + інтеграційний на Mongo (testcontainer) |
| 3.2| Golden-фікстури мапінгу CVE JSON    | Реальний NVD JSON як fixture → очікуваний домен-об'єкт (розширення `CveMappingTests`) |
| 3.3| Contract evals живого API           | `scripts/api-eval.ps1`: підняти API, обійти endpoint'и, звірити з JSON-schema у `docs/` — guardrail від регресії wire-контракту |
| 3.4| Data-quality checks для delta jobs  | Тести на фікстурах (не живій БД): id не порожні, дедупікація, монотонність дат модифікації, розмір дельт у межах очікувань |
| 3.5| Окремий CI job `evals`              | 3.1–3.4 виділити в окремий job, щоб падіння eval-ів було видно окремо від юніт-тестів |

---

## Порядок впровадження (пріоритет)

1. **2.1** warnings-as-errors
2. **2.5** build solution у CI
3. **3.1** golden-dataset keyword search
4. **1.2** deny деструктивних команд
5. **1.4** preflight-скрипт

Пункти 2.1 + 2.5 + 3.1 малі і зв'язані через CI — доцільно одним PR.
