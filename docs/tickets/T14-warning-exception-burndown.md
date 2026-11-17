# T14 — Burn-down списку WarningsNotAsErrors

**Blocked by:** T01 (виконує останній)

## Мета

`Directory.Build.props` закріплює warnings-as-errors, але наявний борг (474 warning'и
станом на 2026-11-17) задокументований як винятки. Цей тікет — трекер, щоб список
винятків тільки спадав.

## Базовий стан (2026-11-17)

| Код      | К-сть | Природа |
|----------|-------|---------|
| CS8618   | 238   | Non-nullable доменні моделі (Cvss*, Impact, Taxonomy, ...) |
| CS1591   | 116   | Відсутні XML-доки на публічних членах (GenerateDocumentationFile=true) |
| CS8601   | 24    | Nullability assignments |
| CS8603/CS8604 | 16+16 | Nullable returns/args |
| CS1573   | 30    | XML-доки: параметр без коментаря |
| CS8600   | 12    | Nullability conversions |
| CS8619   | 8     | Nullability delegate/cast |
| CS8625   | 4     | Null literal to non-nullable |
| NU1603   | 4     | Виправлено в T01 (FluentAssertions pinned 7.0.0) |
| NU1903   | 4     | AutoMapper 13.0.1 — known vulnerability GHSA-rvv3-g6hj-g44x |

## Порядок дій

1. **NU1903**: оновити AutoMapper (13.0.1 → актуальна мінорка без breaking, або 14.x
   з міграцією профілів) і прибрати код зі списку. Найвищий пріоритет — security.
2. **CS8618**: вимагає рішення по моделях (required модифікатор vs nullable vs
   конструктор) — окремий дизайн-дум, робити пакетами по директорії (`Cve/`, `Capec/`).
3. **CS1591/CS1573**: механічне дописування XML-доків, пакетами по проєкту.
4. **CS860x/CS861x**: точкові nullable фікси.

Кожне зменшення списку — окремий commit з номером тікету; правило: код прибирається
з `WarningsNotAsErrors` у тому самому PR, де зникли його останні екземпляри.

## Acceptance criteria

- [ ] Список у Directory.Build.props врешті порожній, і `TreatWarningsAsErrors` діє
      без винятків
- [ ] Жоден код не додається назад
