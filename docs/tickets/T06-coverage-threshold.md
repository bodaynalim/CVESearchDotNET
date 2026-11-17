# T06 — Coverage threshold у CI

**Blocked by:** T01

## Мета

Покриття не може мовчки падати: CI падає нижче порогу.

## Що робить (vertical slice)

1. CI job `api`: `dotnet test` з `--collect:"XPlat Code Coverage"`.
2. Threshold (coverlet-аргументи або наступний step) — стартово 60% (line/branch),
   значення фіксується в описі PR і піднімається згодом окремими тікетами.
3. Звіт coverage додається як артефакт CI (для діагностики, не gate на brain-style).

## Verifiable outcome

- Зниження покриття нижче порогу падає в CI з явним числом.

## Acceptance criteria

- [ ] Threshold налаштований і діє на CI
- [ ] Порог узгоджений (60% стартово) і зафіксований у конфігу
- [ ] Псевдо-тести під поріг не пролазять (тести мають бути осмислені; це culture rule,
      але конфіг не має дозволяти exclude всієї логіки)

## Out of scope

- Публікація coverage в зовнішній сервіс (Codecov/SONAR) — окремо, якщо знадобиться
- Покриття CveUI (Angular) — окремий тікет за потреби
