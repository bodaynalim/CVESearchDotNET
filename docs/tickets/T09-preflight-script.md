# T09 — Preflight скрипт + commit-format

**Blocked by:** T01

## Мета

Обриви ловляться до push: агент і людина мають один command для перевірки перед commit.

## Що робить (vertical slice)

1. scripts/preflight.ps1:
   - build solution (warnings-as-errors)
   - запуск тестів
   - запуск docs link check (node scripts/check-docs.js)
   - перевірка формату commit message: наявність номера тікету (AGENTS.md §4)
2. Правило в AGENTS.md: preflight — обов'язковий step перед commit (і його результат
   фіксується в повідомленні task'а).

## Verifiable outcome

- Скрипт падає на: warning-білді, павному тесті, зламаному doc-link, commit message
  без номера тікету; зелений на чистому стані.

## Acceptance criteria

- [ ] Один command запускатиме всі перевірки (без окремих нагадувань)
- [ ] Повідомлення помилок читабельні: саме який чек впав
- [ ] Скрипт не мутить стан (не фіксить сам, не міняє файли)
- [ ] AGENTS.md оновлений

## Out of scope

- Editorconfig перевірка (T13), publish/CI-механіка
- git hook'и (preflight — свідомий step агента/людини, не примусовий hook; рішення
  може бути переглянуте окремо)
