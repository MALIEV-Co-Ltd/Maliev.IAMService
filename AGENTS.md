# IAM Service Development Guide for Agents

This guide provides essential information for agentic coding agents working in the `Maliev.IAMService` repository.

## 🛠 Commands

### Build & Run
- **Build Solution**: `dotnet build`
- **Run Api**: `dotnet run --project Maliev.IAMService.Api`
- **Apply Database Migrations**: `dotnet ef database update --project Maliev.IAMService.Infrastructure --startup-project Maliev.IAMService.Api`
- **Add Migration**: `dotnet ef migrations add <MigrationName> --project Maliev.IAMService.Infrastructure --startup-project Maliev.IAMService.Api`

### Testing
- **Run All Tests**: `dotnet test --verbosity normal`
- **Run Single Test Class**: `dotnet test --filter "FullyQualifiedName~PermissionsControllerTests"`
- **Run Single Test Method**: `dotnet test --filter "FullyQualifiedName=Maliev.IAMService.Tests.Integration.PermissionsControllerTests.RegisterPermissions_ValidRequest_ReturnsOk"`
- **Generate Coverage**: `dotnet test /p:CollectCoverage=true`

---

## 🏗 Architecture & Tech Stack

- **Framework**: ASP.NET Core 10.0 (C# 13)
- **Database**: PostgreSQL 18 + EF Core 10
- **Cache**: Redis 7.x
- **Messaging**: MassTransit with RabbitMQ
- **API Style**: RESTful with OpenAPI 3.1 + Scalar UI

### Platform Development Mandates (Constitution)
To maintain high performance and low complexity, follow these strict rules:
- ❌ **AutoMapper Banned**: Use explicit manual mapping in constructors or mapping methods.
- ❌ **FluentValidation Banned**: Use standard `System.ComponentModel.DataAnnotations` (`[Required]`, `[EmailAddress]`, etc.).
- ❌ **FluentAssertions Banned**: Use standard xUnit `Assert` methods only.
- ❌ **In-memory Test DB Banned**: Use **Testcontainers** for all integration tests.
- ✅ **TreatWarningsAsErrors**: Must remain enabled.
- ✅ **XML Documentation**: Required for all public classes, methods, and properties.
- ✅ **No Secrets in Code**: Use environment variables or configuration providers.

---

## 📝 Code Style & Conventions

### Imports
- Organize usings: System first, then Third-party, then Maliev namespaces.
- Use file-scoped namespaces: `namespace Maliev.IAMService.Api.Services;`

### Formatting
- Indentation: 4 spaces.
- Braces: All on new lines (K&R style).
- Empty Lines: Single empty line between methods and properties.

### Naming Conventions
- **Classes/Interfaces/Methods/Properties**: `PascalCase`.
- **Private Fields**: `_camelCase`.
- **Local Variables/Parameters**: `camelCase`.
- **Interfaces**: Prefix with `I` (e.g., `IPermissionService`).
- **Async Methods**: Always suffix with `Async` (e.g., `GetPrincipalAsync`).
- **Permissions**: GCP-style `service.resource.action` (e.g., `iam.principals.create`).

### Types & Models
- **DTOs/Requests/Responses**: Use `public record` with `init` properties.
- **Dependency Injection**: Prefer `Scoped` for repositories and services unless a specific reason exists for `Singleton` (e.g., `IRsaKeyProvider`).
- **Required Properties**: Use the `required` modifier for mandatory fields in records.

---

## 💾 Database & Entities

- **Entity Location**: `Maliev.IAMService.Data/Entities/`
- **Naming**: Database tables and columns use `snake_case` (handled by `SnakeCaseNamingExtensions`).
- **Primary Keys**: Use `Guid` for most entities.
- **Repositories**: All DB access must go through the Repository layer in `Maliev.IAMService.Data/Repositories/`.

---

## 🧪 Testing Strategy

We prioritize **Integration Tests** over mock-heavy unit tests.
- **Base Class**: Inherit from `BaseIntegrationTest`.
- **Real Infrastructure**: Tests use `TestWebApplicationFactory` which spins up real PostgreSQL/Redis/RabbitMQ via Testcontainers.
- **Database Cleaning**: Use `await CleanDatabaseAsync()` at the start of tests that depend on a clean state.
- **Assertions**: Stick to `Assert.Equal`, `Assert.NotNull`, etc.

### Testing Strategy (4-Tier Pyramid Context)

This service's tests cover **Tier 1 (Unit)** and **Tier 2 (Service Integration)** of the Maliev testing pyramid:

| Tier | What to Test | Infrastructure |
|------|-------------|---------------|
| **Unit** | Business logic, domain models, service methods with mocked dependencies | None (mocks only) |
| **Service Integration** | API endpoints, database persistence, permission enforcement, input validation | `BaseIntegrationTestFactory` + Testcontainers (Postgres/Redis/RabbitMQ) |

**Tier 3 (System Integration)** — cross-service workflows and event chains — is tested in `Maliev.Aspire.Tests/`.

#### Key Rules
- Use `BaseIntegrationTestFactory<TProgram, TDbContext>` for integration tests (real Testcontainers, never InMemoryDatabase)
- Every MassTransit consumer MUST have a consumer test using `services.AddMassTransitTestHarness()`
- Test naming: `MethodName_StateUnderTest_ExpectedBehavior`
- Minimum 80% code coverage
- Use `[Fact]` for single cases, `[Theory]` for parameterized tests

> Full ecosystem test strategy: `Maliev.Aspire.Tests/TEST_PLAN.md`

---

## 🚨 Error Handling & Logging

- **Exceptions**: Throw specific exceptions (e.g., `InvalidOperationException`, `NotFoundException`).
- **Logging**: Use `ILogger<T>` and prefer High-Performance Logging with `[LoggerMessage]`.
- **Validation**: Rely on Controller `ModelState` validation from Data Annotations.
- **API Responses**: Controllers should return `IActionResult` using standard helpers like `Ok()`, `NotFound()`, `BadRequest()`.

---

## 🔗 Integration Patterns

### IAM Permissions
Permissions are hierarchical. A binding on `orgs/1` automatically grants access to `orgs/1/projects/100` via path matching logic in `PermissionResolver`.

### Service Authentication
Services authenticate using JWTs generated via HMAC-SHA256 with a shared secret.

---

## 🛠 Tooling Integration
- **Cursor/Copilot**: Follow these rules strictly. If a suggested change uses a banned library, reject it and implement it using the approved patterns.
- **OpenTelemetry**: All services are instrumented. Ensure new background tasks or critical paths include proper activity tracking.
- **Build Verification**: Always verify any changes you made with a successful build (`dotnet build`). Never assume any changes will not result in a broken build.


## Git & Version Control — Mandatory Rules

### 🚨 CRITICAL: Always Commit Code Changes (Non-Negotiable)
- **You MUST commit your changes to the local repository after completing any meaningful unit of work.**
- **Never accumulate uncommitted changes.** Do not wait until end of session or until something breaks.
- **Commit early and often** — if a change is meaningful (even a small fix or refactor), commit it.
- **You do NOT need to push to remote** — local commits are sufficient to protect against accidental loss.
- **If you are unsure whether to commit, commit anyway.** Extra commits are harmless; lost work is irreversible.
- This rule applies even if you are just "testing" or "exploring" — use git branches to isolate experimental work and commit those changes too.

### 🚨 CRITICAL: Never Use `git checkout` to Restore Broken Files
- **NEVER use `git checkout` to restore or recover files.** This operation discards uncommitted changes permanently and will result in data loss.
- **To undo/recover from broken files: first commit your current changes, then use `git revert` or `git reset --soft` to safely undo.**

## Database & EF Core — Mandatory Rules

### EF Core Design Package
- ❌ `Microsoft.EntityFrameworkCore.Design` MUST NOT be in Api projects
- ✅ It belongs ONLY in the Infrastructure (or Data) project where migrations live
- Migration commands must target Infrastructure, not Api:
  ```
  dotnet ef migrations add <Name> --project Maliev.<Domain>Service.Infrastructure --startup-project ../Maliev.<Domain>Service.Api
  ```

### PostgreSQL xmin Concurrency — Mandatory Pattern
Use shadow property ONLY. Never add a Xmin/xmin property to domain entities.
```csharp
entity.Property<uint>("xmin").HasColumnType("xid").IsRowVersion();
```
- ❌ Never use `UseXminAsConcurrencyToken()` (removed in Npgsql EF v7)
- ❌ Never use entity property `public uint Xmin { get; set; }` or `public uint xmin { get; set; }`
- ❌ Never use `.Ignore(e => e.Xmin)` — remove the entity property instead
