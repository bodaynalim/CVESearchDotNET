# T13 — Editorconfig compliance gate

**Blocked by:** T01

## Мета

Формат/стиль коду перевіряється механічно проти наявного .editorconfig — до push
(preflight) і в CI.

## Що робить (vertical slice)

1. Preflight (T09): **auto-fix** крок — `dotnet format` (без --verify-no-changes),
   щоб агент сам чинив формат; результат видимий у diff перед commit.
2. CI job `api`: **verify-only** крок — `dotnet format --verify-no-changes --severity warn`;
   неформатна гілка не мерджиться.
3. Якщо verify виявить багато існуючих порушень — окремий коміт "format sweep"
   у межах цього тікету (один mechanical pass, без змішування з логікою).

## Verifiable outcome

- Файл з порушенням .editorconfig падає в CI; preflight виправляє його автоматично.

## Acceptance criteria

- [ ] CI має verify-only крок (не мутить, лише перевіряє)
- [ ] Preflight має auto-fix крок (mutить тільки formatting, не логіку)
- [ ] Немає "format sweep" комітів поза цим тікетом
- [ ] Перевірка не конфликтує з T01 (warnings-as-errors) — послідовність кроків
      зафіксована: спочатку format, потім build

## Implementation notes (2026-11-17, T13 реалізовано)

- Format sweep виконано окремим комітом `T13: mechanical format sweep` — 23 файлів
  production-коду, тільки whitespace/style, verify зелений, жодних змін логіки.
- CI: step `editorconfig compliance (T13)` → `dotnet format --verify-no-changes --severity warn` у job `api`.
- Preflight: verify-крок обов'язковий; локально `-Fix` автоматично чинить.
- CveUI lint/format — досі out of scope (немає скриптів у package.json).

## Out of scope

- Зміна правил .editorconfig (він авторитетний; зміна — окремо)
