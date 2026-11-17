# T08 — Guardrails агента: opencode.json permissions

**Blocked by:** — (стартує одразу)

## Мета

AI-агент фізично не може виконати деструктивні дії чи змінити авторитетні документи
без явного рішення людини.

## Що робить (vertical slice)

1. opencode.json: розширення permission-блоку:
   - bash deny: `rm -rf *`, `dotnet ef database drop*`, `npm publish*`, `dotnet nuget push*`
   - bash ask: `docker * down*`, `mongo*`
   - edit: docs/CODING_STANDARDS.md, docs/adr/*, docs/GLOSSARY.md → ask; AGENTS.md → ask
2. Перевірка, що наявні блоки (build-агент, review) узгоджені з новими правилами.
3. Правило §2 AGENTS.md (Mongo state — не fixture) не дублюється текстом у
   opencode.json — механізм виразно через ask-правило на `mongo*`.

## Verifiable outcome

- Спроба агента виконати `rm -rf` чи редагувати ADR вимагає підтвердження або блокується.

## Acceptance criteria

- [ ] Усі deny-правила перелічені й протестовані вручну (симуляція спроби)
- [ ] Наявні allow-правила (git, grep) не зламані
- [ ] Правила не конфліктують з build-агентом у тому самому файлі

## Out of scope

- Preflight скрипт (T09), review checklist (T10)
- Зміна самих авторитетних документів (тільки permission-механіка)
