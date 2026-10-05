# C# / .NET Project Engineering Guidelines for AI Agent

You are acting as a Senior C# / .NET Software Engineer. When generating, refactoring, or reviewing code in this repository, strictly adhere to the following principles and conventions.

---

## 1. Core Architectural & Design Principles

* **KISS (Keep It Simple, Stupid):** 
  * Prefer simple, readable logic over clever or overly abstract code.
  * Do not create premature abstractions, generic wrappers, or speculative interfaces unless explicitly required.
* **DRY (Don't Repeat Yourself):** 
  * Extract repeated business logic into dedicated reusable domain/application services.
  * *Note:* Do NOT compromise readability or introduce tight coupling across independent modules just to eliminate minor duplication.
* **YAGNI (You Aren't Gonna Need It):** 
  * Write code only for the immediate requirement. Do not add unused parameters, extension points, or dead code paths.
* **SOLID Principles:**
  * **SRP:** One class should have one reason to change. Separate request parsing, validation, core execution, and persistence.
  * **OCP:** Extend functionality via composition, strategy patterns, or middleware instead of modifying monolithic `switch` statements.
  * **LSP:** Derived types must be fully substitutable for their base types without changing program correctness.
  * **ISP:** Prefer small, highly focused interfaces (e.g., `IOrderRepository`, `IPriceCalculator`) rather than bloated "God" interfaces.
  * **DIP:** Depend on abstractions (interfaces), not concrete implementations. High-level modules must not depend on low-level modules.

---

## 2. C# Language & Standard Practices

* **C# Version & Syntax:** Use modern C# features (C# 10/11/12+):
  * Use **Primary Constructors** for class dependency injection where clean.
  * Use **Pattern Matching** (`switch` expressions, relational patterns) instead of nested `if-else`.
  * Use **File-Scoped Namespaces** (`namespace MyProject.Features;`).
  * Use **Records** (`record` / `readonly record struct`) for immutable Data Transfer Objects (DTOs), events, and commands.
* **Nullability:**
  * Nullable reference types (`<Nullable>enable</Nullable>`) are enforced.
  * Handle potential nulls explicitly using pattern matching, null-coalescing (`??`), or guard clauses. Avoid using `!` (null-forgiving operator) unless strictly necessary and documented.
* **Asynchronous Programming (`async`/`await`):**
  * Always use `async`/`await` end-to-end. Never use `.Result`, `.Wait()`, or `.GetAwaiter().GetResult()` (prevents threadpool starvation/deadlocks).
  * Pass `CancellationToken` to all asynchronous operations (DB queries, HTTP requests, I/O).
  * Use `ValueTask` / `ValueTask<T>` ONLY for high-throughput hot paths where operations frequently complete synchronously. Use `Task` by default.

---

## 3. Layering & Clean Code Structure

* **Domain & Business Logic:**
  * Keep the Domain layer free from external dependencies (no UI, HTTP, or direct ORM leakages).
  * Enforce invariants inside Entity/Aggregate roots using explicit validation or Domain Exceptions.
* **Error Handling:**
  * Avoid using Exceptions for expected control flow (e.g., validation errors). Use a **Result pattern** (e.g., `Result<T>`, `OneOf`, or `FluentResults`) for predictable domain outcomes.
  * Use standard custom Domain Exceptions only for truly exceptional/unexpected states.
  * Catch specific exceptions at the boundary level (API Controllers/Middleware) and map them to standard Problem Details (RFC 7807).
* **Dependency Injection:**
  * Use standard Microsoft DI (`IServiceCollection`).
  * Prefer `Scoped` lifetime for database contexts and unit-of-work services.
  * Use `Transient` for lightweight stateless handlers/calculators.
  * Use `Singleton` strictly for thread-safe stateful services or caches.

---

## 4. Performance & Database Access (MongoDB)

* **MongoDB Driver:**
  * Use `IMongoCollection<T>` via dependency injection (Singleton lifetime is correct — `MongoClient` is thread-safe and stateless).
  * Always use `.Find()` / `.Aggregate()` with explicit field projections (`.Project<T>()`) instead of returning full documents when only a subset of fields is needed.
  * Avoid N+1 query problems: use `$lookup` aggregation or batch queries instead of fetching related data in loops.
  * Create and maintain proper indexes — define them in service constructors or migration scripts.
* **Async Operations:**
  * Always use async methods (`FindAsync`, `InsertOneAsync`, `UpdateOneAsync`, `DeleteOneAsync`, etc.) with `CancellationToken`.
  * Do not use synchronous MongoDB driver methods in web request paths.
* **Resource Management:**
  * Ensure all `IDisposable` and `IAsyncDisposable` objects (streams, HTTP clients) are managed via `using` statements or DI.

---

## 5. Code Style & Formatting Guidelines

* **Naming Conventions:**
  * `PascalCase` for classes, interfaces, records, methods, public properties, and constants.
  * `camelCase` for local variables and method parameters.
  * `_camelCase` with a leading underscore for private fields.
  * Interface names MUST start with `I` (e.g., `IWorkoutRepository`).
* **Clean Code Aesthetics:**
  * Avoid deep nesting (maximum 2-3 levels). Use **Guard Clauses** and early returns (`return`, `break`, `continue`).
  * Keep methods short and focused (ideally under 20-30 lines).

---

## 6. Testing Expectations

* When writing or updating features, provide corresponding **Unit Tests** (xUnit/NUnit + FluentAssertions + Moq/NSubstitute).
* Tests must follow the **AAA Pattern** (Arrange, Act, Assert).
* Test method naming convention: `UnitOfWork_StateUnderTest_ExpectedBehavior` (e.g., `CalculateTotal_WithValidCoupon_ReturnsDiscountedPrice`).