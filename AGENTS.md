# IAM Service Development Guide for Agents

This guide provides essential information for agentic coding agents working in the `Maliev.IAMService` repository.

> **Workspace root** `B:\maliev` contains **41 independent git repos**. Each `Maliev.*` folder and `maliev-gitops` is its own repo. There is no single repo at the workspace root. Always work within the target service directory.

---

## Build, Test & Lint Commands

All commands run from within this service directory (`B:\maliev\Maliev.IAMService`).

```powershell
# Build (treats warnings as errors — all must be fixed)
dotnet build Maliev.IAMService.slnx

# Run all tests
dotnet test Maliev.IAMService.slnx --verbosity normal

# Run a single test method
dotnet test --filter "FullyQualifiedName~PermissionsControllerTests.RegisterPermissions_ValidRequest_ReturnsOk"

# Run all tests in a class
dotnet test --filter "FullyQualifiedName~PermissionsControllerTests"

# Run with code coverage
dotnet test Maliev.IAMService.slnx --collect:"XPlat Code Coverage"

# Format check
dotnet format Maliev.IAMService.slnx

# EF Core migrations (Infrastructure project only)
dotnet ef migrations add <Name> --project Maliev.IAMService.Infrastructure --startup-project Maliev.IAMService.Infrastructure

# Run Api
dotnet run --project Maliev.IAMService.Api

# Apply Database Migrations
dotnet ef database update --project Maliev.IAMService.Infrastructure --startup-project Maliev.IAMService.Api
```

---

## Architecture & Tech Stack

- **Framework**: ASP.NET Core 10.0 (C# 13)
- **Database**: PostgreSQL 18 + EF Core 10
- **Cache**: Redis 7.x
- **Messaging**: MassTransit with RabbitMQ
- **API Style**: RESTful with OpenAPI 3.1 + Scalar UI

### Workspace Structure (this service)
```
Maliev.IAMService/
├── Maliev.IAMService.Api/              # Controllers, Consumers, Middleware
├── Maliev.IAMService.Application/      # Use cases, DTOs, Interfaces, Handlers
├── Maliev.IAMService.Domain/           # Entities, value objects, domain interfaces
├── Maliev.IAMService.Data/             # EF Core DbContext, Repositories, Entities
├── Maliev.IAMService.Infrastructure/   # HTTP clients, external service integrations
├── Maliev.IAMService.Tests/            # Unit + Integration tests (xUnit)
├── Directory.Build.props               # Central package versioning
└── Maliev.IAMService.slnx             # Solution file (.slnx preferred over .sln)
```

---

## Banned Libraries (Build Will Fail)

| Banned | Use Instead |
|--------|-------------|
| AutoMapper | Manual mapping extensions |
| FluentValidation | DataAnnotations or manual validation |
| FluentAssertions | Standard xUnit `Assert.*` |
| Swashbuckle/Swagger | Scalar (at `/{service}/scalar`) |
| InMemoryDatabase (EF Core) | Testcontainers with real PostgreSQL |

---

## Code Style & Conventions

### C# Naming & Formatting
- **Namespaces**: File-scoped (`namespace Maliev.IAMService.Api.Services;`)
- **Classes/Methods/Properties**: `PascalCase`
- **Private fields**: `_camelCase` (underscore prefix)
- **Parameters/locals**: `camelCase`
- **Async methods**: Suffix with `Async` (e.g., `GetPrincipalAsync`)
- **Interfaces**: Prefix with `I` (e.g., `IPermissionService`)
- **Permissions**: GCP-style `{domain}.{plural-resource}.{action}` as `public const string` in a `Permissions` static class
  - Valid: `iam.permissions.create`, `iam.roles.list`
  - Invalid: `iam.permission.create` (singular), `iam.create` (missing resource)
- **XML docs**: Required on ALL public methods and properties
- **Nullable**: Enabled (`<Nullable>enable</Nullable>`). Use `?` explicitly
- **Imports**: System first, then third-party, then local. Alphabetize within groups. Remove unused `using`
- **Braces**: Allman style (new line) for methods and control structures. Expression-bodied for properties/accessors
- **Indentation**: 4 spaces, LF line endings, UTF-8, trim trailing whitespace

### C# Patterns
- **DI**: Constructor injection with `private readonly` fields
- **Controllers**: `[ApiController]`, `[ApiVersion("1")]`, `[Route("iam/v{version:apiVersion}")]`
- **Logging**: `ILogger<T>` with structured placeholders (never interpolate): `_logger.LogInformation("Processing {PrincipalId}", principalId)`
- **Error handling**: Global exception middleware. Return `ProblemDetails` / `ErrorResponse` DTOs. Never expose stack traces
- **Manual mapping**: Static extension methods (`ToDto()`, `ToEntity()`). AutoMapper is banned
- **Validation**: `System.ComponentModel.DataAnnotations` on DTOs. FluentValidation is banned
- **DTOs/Requests/Responses**: Use `public record` with `init` properties. Use the `required` modifier for mandatory fields.
- **DI Scopes**: Prefer `Scoped` for repositories and services unless a specific reason exists for `Singleton` (e.g., `IRsaKeyProvider`).

---

## Database & Entities

- **Entity Location**: `Maliev.IAMService.Data/Entities/`
- **Naming**: Database tables and columns use `snake_case` (handled by `SnakeCaseNamingExtensions`).
- **Primary Keys**: Use `Guid` for most entities.
- **Repositories**: All DB access must go through the Repository layer in `Maliev.IAMService.Data/Repositories/`.

---

## Testing Rules

- **Framework**: xUnit with standard `Assert` (`Assert.Equal`, `Assert.NotNull`, etc.)
- **Naming**: `MethodName_StateUnderTest_ExpectedBehavior` or `HTTP_METHOD_Path_Scenario_ExpectedStatus`
- **Coverage**: Minimum 80% per service
- **Integration tests**: `BaseIntegrationTestFactory<TProgram, TDbContext>` with Testcontainers (PostgreSQL, Redis, RabbitMQ). Never InMemoryDatabase
- **System tests** (Tier 3): `AspireTestFixture` with `[Collection("AspireDomainTests")]` — shared AppHost, never one per class
- **Eventual consistency**: Use `TestHelpers.WaitForAsync`. Never `Task.Delay`
- **MassTransit consumers**: Must have consumer tests using `AddMassTransitTestHarness()`

### Testing Strategy (4-Tier Pyramid Context)

This service's tests cover **Tier 1 (Unit)** and **Tier 2 (Service Integration)** of the Maliev testing pyramid:

| Tier | What to Test | Infrastructure |
|------|-------------|---------------|
| **Unit** | Business logic, domain models, service methods with mocked dependencies | None (mocks only) |
| **Service Integration** | API endpoints, database persistence, permission enforcement, input validation | `BaseIntegrationTestFactory` + Testcontainers (Postgres/Redis/RabbitMQ) |

**Tier 3 (System Integration)** — cross-service workflows and event chains — is tested in `Maliev.Aspire.Tests/`.

> Full ecosystem test strategy: `Maliev.Aspire.Tests/TEST_PLAN.md`

---

## Error Handling & Logging

- **Exceptions**: Throw specific exceptions (e.g., `InvalidOperationException`, `NotFoundException`).
- **Logging**: Use `ILogger<T>` with structured placeholders (never interpolate). Prefer High-Performance Logging with `[LoggerMessage]`.
- **Validation**: Rely on Controller `ModelState` validation from Data Annotations.
- **API Responses**: Controllers should return `IActionResult` using standard helpers like `Ok()`, `NotFound()`, `BadRequest()`.

---

## Integration Patterns

### IAM Permissions
Permissions are hierarchical. A binding on `orgs/1` automatically grants access to `orgs/1/projects/100` via path matching logic in `PermissionResolver`.

### Service Authentication
Services authenticate using JWTs generated via HMAC-SHA256 with a shared secret.

---

## Mandatory Rules

- **`TreatWarningsAsErrors = true`**: Zero warnings allowed. No suppression
- **`[RequirePermission("domain.resources.action")]`**: On all endpoints, not plain `[Authorize]`
- **API versioning**: All routes versioned (`v1/`)
- **Service prefix**: Routes prefixed with service domain (e.g., `/iam`)
- **Scalar docs**: Configured at `/iam/scalar`
- **Secrets**: Never hardcoded. Use GCP Secret Manager or environment variables
- **Async/await**: All the way down. Pass `CancellationToken`
- **EF Core Design package**: Only in Infrastructure project, never in Api
- **PostgreSQL xmin**: Shadow property only — `entity.Property<uint>("xmin").HasColumnType("xid").IsRowVersion()`. Never add entity property
- **Temporary files**: Generate in `/temp` folder, clean up afterwards

---

## Database & EF Core — Mandatory Rules

### EF Core Design Package
- ❌ `Microsoft.EntityFrameworkCore.Design` MUST NOT be in Api projects
- ✅ It belongs ONLY in the Infrastructure (or Data) project where migrations live
- Migration commands must target Infrastructure, not Api:
  ```
  dotnet ef migrations add <Name> --project Maliev.IAMService.Infrastructure --startup-project Maliev.IAMService.Infrastructure
  ```

### PostgreSQL xmin Concurrency — Mandatory Pattern
Use shadow property ONLY. Never add a Xmin/xmin property to domain entities.
```csharp
entity.Property<uint>("xmin").HasColumnType("xid").IsRowVersion();
```
- ❌ Never use `UseXminAsConcurrencyToken()` (removed in Npgsql EF v7)
- ❌ Never use entity property `public uint Xmin { get; set; }` or `public uint xmin { get; set; }`
- ❌ Never use `.Ignore(e => e.Xmin)` — remove the entity property instead

---

## Git Rules

- Each `Maliev.*` folder is an independent git repo. `cd` into it before git commands
- **Commit early and often** after every meaningful unit of work. Do not accumulate changes
- **Never use `git checkout` to restore files** — commit first, then `git revert` or `git reset --soft`
- Feature branches merged to `develop` via PR. Do not push without being asked

---

## Tooling Integration
- **Cursor/Copilot**: Follow these rules strictly. If a suggested change uses a banned library, reject it and implement it using the approved patterns.
- **OpenTelemetry**: All services are instrumented. Ensure new background tasks or critical paths include proper activity tracking.
- **Build Verification**: Always verify any changes you made with a successful build (`dotnet build`). Never assume any changes will not result in a broken build.
