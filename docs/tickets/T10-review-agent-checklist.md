# T10 — Review agent checklist

**Blocked by:** — (стартує одразу)

## Мета

Two-axis review (standards за CODING_STANDARDS.md + spec) виконується послідовно, з
обов'язковим чеклистом, а не "на розсуд" агента.

## Що робить (vertical slice)

1. Розширення .opencode/agent/review.md (або skills/code-review SKILL.md — залежно
   від того, де живе лоґіка) обов'язковим чеклистом:
   - ADR-и в зоні змін не порушені (перелічити, які перевірено)
   - Wire contract — camelCase (ADR-0001)
   - Keyword search семантика (ADR-0002)
   - Mongo правила (bulk upserts з конкретними id — ADR-0003)
   - Terminal цілісність: тести запущені, зачеплені suite'и зелені
2. Вихід review — структурований: по кожному пункту ok/fail + посилання.

## Verifiable outcome

- Запуск review-агента на тестовому diff дає заповнений чеклист, а не вільний текст.

## Acceptance criteria

- [ ] Чеклист обов'язковий (агент не може завершити без заповнення)
- [ ] Чеклист посилається на конкретні ADR/CODING_STANDARDS пункти, а не на "стиль"
- [ ] Не дублює те, що вже механізовано в тестах (T04/T05) — посилається на них

## Out of scope

- Permissions (T08), preflight (T09)
- Автоматичний запуск review в CI
