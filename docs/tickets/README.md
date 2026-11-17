# Tickets: Guardrails & Evals

Розбивка спеку [../guardrails-and-evals-spec.md](../guardrails-and-evals-spec.md)
(джерело — [guardrails-and-evals-plan.md](../guardrails-and-evals-plan.md)) на
tracer-bullet вертикальні зрізи.

## Граф блокувань

```
T1 ──┬── T6   (coverage threshold)
     ├── T9   (preflight)
     └── T13  (editorconfig gate)
T2 ──┐
     ├── T7  (CI job evals)
T3 ──┘
T4 ──── T11 (api contract evals)
```

Решта тікетів (T5, T8, T10, T12) не мають блокерів і стартують одразу.

## Рекомендований перший PR

**T1 + T2** (малі, зв'язані через CI).

## Індекс

| Тікет  | Назва                                        | Blocked by |
|--------|----------------------------------------------|------------|
| [T01](T01-build-hardening.md)            | Build hardening: warnings-as-errors + повний build у CI | — |
| [T02](T02-keyword-golden-dataset.md)     | Golden-dataset для keyword search | — |
| [T03](T03-cve-mapping-golden-fixture.md) | Golden CVE mapping fixture | — |
| [T04](T04-rest-contract-snapshots.md)    | Contract snapshot тести REST (camelCase) | — |
| [T05](T05-architecture-tests.md)         | Architecture tests (шаринг проєктів) | — |
| [T06](T06-coverage-threshold.md)         | Coverage threshold у CI | T1 |
| [T07](T07-ci-evals-job.md)               | CI job `evals` | T2, T3 |
| [T08](T08-agent-permissions.md)          | Guardrails агента: opencode.json permissions | — |
| [T09](T09-preflight-script.md)           | Preflight скрипт + commit-format | T1 |
| [T10](T10-review-agent-checklist.md)     | Review agent checklist | — |
| [T11](T11-api-contract-evals.md)         | API contract evals скрипт | T4 |
| [T12](T12-delta-job-data-quality.md)     | Data-quality інваріанти delta jobs | — |
| [T13](T13-editorconfig-gate.md)          | Editorconfig compliance gate | T1 |
| [T14](T14-warning-exception-burndown.md) | Burn-down списку WarningsNotAsErrors | T1 |

## Загальні правила для всіх тікетів

- Дотримуватись [CODING_STANDARDS.md](../CODING_STANDARDS.md); нові терміни — одразу в [GLOSSARY.md](../GLOSSARY.md).
- ADR не змінювати; якщо рішення спеку конфліктує з ADR — спинитись і оновити ADR окремо.
- Commit message містить номер тікету (AGENTS.md §4).
- MongoDB state не використовується як fixture (AGENTS.md §2).
- Валідація: typecheck, зачеплені suite'и першими, повні suite'и наприкінці; перед commit — preflight (після T9).
