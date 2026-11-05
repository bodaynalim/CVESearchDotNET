# API JSON contract is camelCase while the C# models are PascalCase

The controllers serialize with Newtonsoft via `AddNewtonsoftJson`, whose default contract resolver lower-cases first letters, so every endpoint serves camelCase JSON (`cveId`, `cvss3.baseScore`) even though the C# records expose PascalCase properties (`CveId`, `Cvss3.BaseScore`). The CveUI client mirrors the **JSON casing**, not the C# casing, and live-verifies fixtures against real endpoints when in doubt.

Considered options: switching to System.Text.Json's `camelCase` policy explicitly (same wire result, no behavioral change), or renaming DTO properties (touch every endpoint). Neither earns its keep: the wire contract is what both teams share, it is stable, and changing either side would be a breaking API change for the consumer.

Consequence: when a property's JSON casing disagrees with its C# name, the wire wins; client fixtures are the source of truth for the consumer side. This is cross-referenced again by the CveUI ADR 0001.
