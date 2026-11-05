# Engineering Guidelines for AI Agents

You are acting as a Senior C# / .NET Software Engineer. This file covers **agent workflow and environment caveats only**. How code must be written is defined in [`docs/CODING_STANDARDS.md`](docs/CODING_STANDARDS.md) — always read and follow it first; it is the authoritative, repo-specific standard that code review enforces.

## 1. Authoritative documents (read before acting)

- [`docs/CODING_STANDARDS.md`](docs/CODING_STANDARDS.md) — coding standard for the .NET API projects (layering, REST contract, Mongo rules, testing).
- [`AGENTS.md`](AGENTS.md) — this file (agent workflow).
- [`docs/GLOSSARY-MAP.md`](GLOSSARY-MAP.md) → [`docs/GLOSSARY.md`](GLOSSARY.md) (API domain terms); write new settled terms in immediately, not later.
- `docs/adr/*.md` — architectural decisions (camelCase wire contract, keyword search semantics). Changing a recorded decision requires updating its ADR, not bypassing it.
- `CveUI/` has its own conventions; when editing it, consult `CveUI/GLOSSARY.md` and the UI test seam norms established by `CveUI/src/app/testing/boot-app.ts`.

## 2. Filesystem search caveats (hard)

- **Dot-directories are hidden from glob/grep tools** (e.g. `.opencode/`, `.github/`, `.vs/`). A glob like `.opencode/**` may return "No files found" even when the directory exists. Before concluding a dot-directory or its files do not exist, verify with `Get-ChildItem -Force` (PowerShell) or a directory read.
- The MongoDB delta jobs regenerate data; never treat database state as a fixture.

## 3. Environment notes

- The API runs at `http://localhost:5254` (launchSettings); Hangfire dashboard at `/hangfire` with basic auth from `appsettings.Development.json`.
- Long-running servers (API, Angular dev server) are background processes: restart **and rebuild** the API after changing backend code — editing only the database-visible state does nothing to the running binary. Watch out for DLL lock contention while the API is running (`MSB3027`): stop the process, build/test, restart.
- Windows PowerShell quirks worth remembering:
  - `npm.ps1` may be blocked — use `npm.cmd`.
  - `Get-Content`/`Set-Content` without an encoding argument mangles UTF-8 on this machine (CP1251 mojibake) — use explicit encodings or a byte-safe tool for any file containing non-ASCII text.

## 4. Working discipline

- Fetch the ticket from the tracker and state its title before starting; implement → validate (typecheck, affected suites first, full suites at the end) → two-axis review (standards per `docs/CODING_STANDARDS.md` + spec) → commit (message references the ticket number).
- Fact-finding is your job: explore the codebase before asking the user anything you can look up. Decisions are the user's.
- Reported bugs get a root-cause fix at the right layer, not a symptom patch; where the fixed logic is pure, add a regression test the same day.

## 5. Sanctioned consulting shortcuts you may not take

When unsure, prefer reading these files over guessing: `Web/Cve.Net.Search.Web/Program.cs` (DI wiring), `Infrastructure/.../AutoMapper/VulnerabilitiesProfile.cs` (model mapping rules), `Web/.../Controllers/*` (route style), `Tests/Cve.Net.Search.Tests/*` (test style). Do not invent endpoints, columns, or conventions that don't exist — verify against code first.
