# T01 — Build hardening: warnings-as-errors + повний build у CI

**Blocked by:** — (стартує одразу)

## Мета

Компіляторні warning'и та зламаний не-тестовий проєкт не можуть потрапити в main: build падає до merge.

## Що робить (vertical slice)

1. Спільні налаштування solution-рівня (Directory.Build.props або еквівалент):
   `TreatWarningsAsErrors=true`, `Nullable=enable`, `AnalysisLevel=latest-recommended`.
2. CI job `api` (.github/workflows/ci.yml): перед тестами — `dotnet build Cve.Net.Search.sln -warnaserror` (або наслідує свойство без прапорця).
3. Закріплення рішення в docs/CODING_STANDARDS.md (розділ про build warnings).

## Verifiable outcome

- CI падає, якщо будь-який проєкт solution'а дає warning або не збирається.
- Локально: `dotnet build Cve.Net.Search.sln` зелений без попереджень.

## Acceptance criteria

- [ ] Спільні props застосовані до всіх C# проєктів solution'а
- [ ] CI збирає весь solution, а не лише тест-проєкт
- [ ] CODING_STANDARDS.md оновлений
- [ ] Немає придушень (`#pragma warning disable`, NoWarn) без явного коментаря-обґрунтування

## Out of scope

- Виправлення наявного технічного боргу поза тим, що треба для зеленого warning-as-error білда (якщо боргу багато — ескалація перед T1, не мовчазне придушення).
- Покриття (T06), аналізатори вимогою-незалежні від стандарту (T05).
