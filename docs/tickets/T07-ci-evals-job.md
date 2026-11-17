# T07 — CI job `evals`

**Blocked by:** T02, T03

## Мета

Golden/eval-тести видно окремо від юніт-тестів: падіння eval-ів не зливається з падінням
юніт-тестів у статусі PR.

## Що робить (vertical slice)

1. Новий job `evals` у .github/workflows/ci.yml.
2. У тест-наборі — фільтр/категорія (trait/category), що виділяє golden/eval-тести.
3. Job запускає тільки eval-набір; job `api` продовжує запускати решту (без дублювання
   eval-ів у статусі `api`, щоб статуси були ортогональні).

## Verifiable outcome

- Навмисне падіння golden-тесту дає статус саме `evals`, не `api`.

## Acceptance criteria

- [ ] Job `evals` зелений на main
- [ ] Розділення через категорію/фільтр, не через окремий дубльований код тестів
- [ ] Parallelism: `evals` не блокує `api` (незалежні jobs)

## Out of scope

- Самі eval-и (T02, T03, T12); живий API eval (T11)
- Нічні/регресивні величі evals — поки не треба
