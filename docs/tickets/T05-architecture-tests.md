# T05 — Architecture tests (шаринг проєктів)

**Blocked by:** — (стартує одразу)

## Мета

Шаринг, закріплений в CODING_STANDARDS.md, механізований: збірка падає, якщо
Domain/Application почнуть залежати від Infrastructure/Web.

## Що робить (vertical slice)

1. Тест (NetArchTest.Rules або простий reflection-тест — обрати на користь
   мінімуму залежностей) у Tests/Cve.Net.Search.Tests або окремому arch-тест-проєкті.
2. Правила:
   - Domain не референся Infrastructure, Web, Application (за стандартом)
   - Application не референся Infrastructure, Web (за стандартом)
3. Прогнати на поточному коді — якщо є наявні порушення, зафіксувати як documented
   exceptions або ескалувати перед мерджем.

## Verifiable outcome

- Додавання посилання Domain → Infrastructure в csproj падає в тестах з явним повідомленням.

## Acceptance criteria

- [ ] Правила шарингу закодовані й запускаються в звичайному `dotnet test`
- [ ] Наявні порушення або відсутні, або явно задокументовані
- [ ] Обране рішення (NetArchTest vs reflection) обґрунтоване в описі PR

## Out of scope

- Проверки стилю коду (editorconfig — T13), тестових конвенцій
