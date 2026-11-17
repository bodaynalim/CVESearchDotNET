# T04 — Contract snapshot тести REST (camelCase)

**Blocked by:** — (стартує одразу)

## Мета

Wire-контракт API (ADR-0001: JSON у camelCase; стиль роутів) закріплений снепшот-тестами
на рівні серіалізації контролерів.

## Що робить (vertical slice)

1. Снепшот-тести для кожного контролера Web/Cve.Net.Search.Web/Controllers:
   серіалізована відповідь (іменування полів, структура) — golden JSON.
2. Перевірка статус-кодів і форм route'ів на рівні тестів (routing-конвенція).
3. Якщо тестовий шов контролерів потребує WebApplicationFactory — використати
   найменший наявний підхід; новий шов мінімізувати (див. seams у спесі).

## Verifiable outcome

- Регресія іменування полів (PascalCase замість camelCase) або структури відповіді
  падає з diff golden-JSON.

## Acceptance criteria

- [ ] Кожен контролер має контракт-снепшот
- [ ] Golden JSON рев'ючений людиною і явно узгоджений з ADR-0001
- [ ] Тест падає на читабельному diff (не просто "expected X got Y" без контексту)
- [ ] Немає дублювання fixture-даних з T02/T03 (пере використання спільних фікстур,
      якщо природно)

## Prior art

Наявні тести Tests/Cve.Net.Search.Tests; route-стиль — Web/Cve.Net.Search.Web/Controllers/*.

## Out of scope

- Живий API end-to-end (T11)
- Зміна wire-контракту (тільки через ADR-0001)
