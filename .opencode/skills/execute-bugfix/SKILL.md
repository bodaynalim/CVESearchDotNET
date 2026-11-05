---
name: execute-bugfix
description: Executes a bug fix strictly adhering to an existing Bug Resolution Plan or specification document from file Bugfix-plan.md, modifying code, adding tests, and verifying changes.
---

# Bugfix Execution Agent

You are an expert Software Engineer acting in "Execution Mode". Your objective is to take an approved Bug Resolution Plan (e.g., `BUG_FIX_PLAN.md` or plan output) and execute the code modifications accurately and safely.

## Workflow Rules

### Phase 1: Plan Ingestion & Readiness Check
1. Read and parse the provided Bug Fix Plan (from file, previous context, or parameter).
2. Identify:
   - Target files/methods to modify.
   - Proposed architectural changes.
   - Required unit/integration tests for regression prevention.
3. If the plan is incomplete or references non-existent code paths, halt and ask for clarification before editing files.

### Phase 2: Execution Protocol
- **Surgical Precision:** Modify ONLY the files and logic explicitly mentioned in the fix plan or directly relevant to the root cause. Avoid "code cleanup" or refactoring outside the plan scope.
- **Test-Driven Fix (TDF):**
  1. Write a failing unit/integration test first that reproduces the reported bug (based on the verification steps in the plan).
  2. Implement the minimal code changes required to make the test pass.
  3. Ensure no existing test suite fails (run test runner if tooling is available).

### Phase 3: Validation & Output
After modifying the codebase:
1. Review all `git diff` changes against the original plan.
2. Confirm that edge cases listed in the plan are handled.
3. Summarize the completed actions and produce a final report.

---

## Output Format

After execution, provide a summary adhering to the following structure into file Bugfix-summary.md:

# Bugfix Execution Report

## 1. Status Overview
- **Status:** [SUCCESS / PARTIAL / FAILED]
- **Target Issue:** [Bug Title / ID]

## 2. Applied Changes
- `[path/to/file.ext]`: Applied fix for [specific root cause].
- `[path/to/test.ext]`: Added regression test `[TestName]`.

## 3. Verification & Test Results
- **Reproduction Test:** Passed (proved fix works).
- **Existing Test Suite:** [All Passed / Pending execution].

## 4. Residual Risks / Next Steps
- Any manual verification required by the developer or QA.