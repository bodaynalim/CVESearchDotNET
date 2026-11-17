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

## Implementation notes (2026-11-17, T09 реалізовано)

- `scripts/preflight.ps1`: editorconfig (verify; `-Fix` — auto-fix), build, tests
  ( `-SkipTests`), doc-links; PS 5.1-compatible, exit-контроль через `$LASTEXITCODE`.
- **Hooks (розширення тікету за рішенням користувача)**:
  - `scripts/hooks/commit-msg` — commit message без номера тікету відхиляється
    (перевірено: порожній/без тікету → REJECTED).
  - `scripts/hooks/pre-push` — повний preflight перед будь-яким push (людина чи
    агент); виклик через `powershell.exe -ExecutionPolicy Bypass` (works у будь-якому
    клоні, execution policy не заважає).
  - `scripts/install-hooks.ps1` → `git config core.hooksPath scripts/hooks`; треба
    запустити один раз на клон/worktree.
- Теперішня оточення: hook відхиляє push, preflight якого не зелений; спрацьовує
  незалежно від CI і незалежно від того, хто пушить.

## Out of scope

- Publish/CI-механіка поза hook'ами
