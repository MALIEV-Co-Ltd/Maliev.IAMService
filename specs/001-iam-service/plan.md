# Implementation Plan: IAM Service

**Branch**: `001-iam-service` | **Date**: 2025-12-20 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/001-iam-service/spec.md`

## Summary

Centralized Identity and Access Management (IAM) service implementing Google Cloud IAM-style permission and role management for the Maliev microservices platform. The service follows a **principal-first architecture** where IAM owns all principals (universal identity), Customer/EmployeeService store business profiles that reference principal_id, and permissions are embedded in JWTs for <10ms authorization checks. Core features include permission registration, role management with global and resource-scoped bindings, service account authentication, JWT token issuance with RS256 signing, and comprehensive audit logging.

## Technical Context

**Language/Version**: C# / .NET 10.0
**Primary Dependencies**:
- **Maliev.Aspire.ServiceDefaults** (NuGet from private feed) - Platform-wide configurations
- ASP.NET Core 10.0, Entity Framework Core 10.0
- PostgreSQL 18 via Npgsql.EntityFrameworkCore.PostgreSQL
- Redis via StackExchange.Redis
- RabbitMQ via MassTransit.RabbitMQ
- Microsoft.AspNetCore.Cryptography.KeyDerivation for PBKDF2 password hashing (native .NET)
**Storage**: PostgreSQL 18 (snake_case naming convention)
**Testing**: xUnit with Testcontainers for integration tests
**Target Platform**: Linux containers (Kubernetes deployment)
**Project Type**: Web API microservice (RESTful)
**Performance Goals**:
- Permission checks: <10ms (95th percentile, cached)
- Support 1000+ concurrent permission checks/second
- Permission registration: 100+ permissions in <2 seconds
- Token issuance: <200ms
**Constraints**:
- Horizontal scaling via stateless instances
- Shared Redis cache across all instances
- Cache TTL: 5 minutes (permissions), 30 minutes (roles)
- All endpoints require authentication
- `/iam` prefix for Kubernetes ingress routing
**Scale/Scope**:
- Multi-tenant platform supporting 10k+ users
- 100+ microservices registering permissions
- 90-day audit log retention
- JWT tokens with embedded permissions
- RS256 asymmetric signing for security

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

**Status**: No project-specific constitution defined - using standard .NET microservice best practices

**Applied Standards**:
- ✅ **Maliev.Aspire.ServiceDefaults integration** - Platform-wide observability, health checks, and infrastructure
- ✅ RESTful API design with OpenAPI documentation (Scalar UI)
- ✅ Repository pattern for data access
- ✅ Dependency injection for testability
- ✅ Structured logging (JSON format via OpenTelemetry)
- ✅ Prometheus metrics exposure (via ServiceDefaults)
- ✅ Distributed tracing support (OpenTelemetry + OTLP exporter)
- ✅ Test-first development (unit + integration tests)
- ✅ Horizontal scaling capability (stateless design)
- ✅ API versioning (URL segment: /iam/v1/...)

## CRITICAL: Principal-First Model

This IAM implementation follows a **principal-first architecture** where:

1. **IAM owns all principals** - `principal_id` is the universal identifier
2. **Customer/Employee are profiles** - They reference `principal_id`, not own identity
3. **AuthService integration** - IAM provides permission resolution during login
4. **JWT-embedded permissions** - <10ms authorization checks (no external calls)
5. **IAM not on hot path** - Only called during login/refresh, not per-request

### Key API Endpoint for AuthService Integration

```http
POST /iam/v1/auth/resolve-permissions
Authorization: Bearer <service-account-token>
{
  "principalId": "uuid",
  "includeResourceScoped": false
}

Response:
{
  "principalId": "uuid",
  "permissions": ["invoice.invoices.create", ...],
  "roles": ["invoice-manager", ...],
  "resolvedAt": "2024-01-15T10:30:00Z",
  "cacheUntil": "2024-01-15T10:35:00Z"
}
```

This endpoint is called by AuthService after credential validation to embed permissions in JWT.

### Implementation Priority Order

1. **FIRST**: Principal Management + Permission Resolution
2. **SECOND**: Permission/Role Registration
3. **THIRD**: Role Bindings
4. **FOURTH**: Service Accounts
5. **FIFTH**: Audit Logging

## Project Structure

### Documentation (this feature)

```text
specs/001-iam-service/
├── plan.md              # This file (/speckit.plan command output)
├── research.md          # Phase 0 output (technology decisions)
├── data-model.md        # Phase 1 output (database schema)
├── quickstart.md        # Phase 1 output (getting started guide)
├── contracts/           # Phase 1 output (OpenAPI spec)
│   └── openapi.yaml
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
```

### Source Code (repository root)

```text
Maliev.IAMService/
├── Maliev.IAMService.Api/              # REST API
│   ├── Controllers/
│   │   ├── PrincipalsController.cs     # Principal management (FIRST PRIORITY)
│   │   ├── PermissionsController.cs    # Permission registration & queries
│   │   ├── RolesController.cs          # Role management
│   │   ├── BindingsController.cs       # User/SA role bindings
│   │   ├── AuthController.cs           # JWT token issuance & permission resolution
│   │   └── AuditController.cs          # Audit log queries
│   ├── Services/
│   │   ├── PrincipalService.cs         # Principal CRUD and lookup (FIRST)
│   │   ├── PermissionService.cs        # Permission business logic
│   │   ├── RoleService.cs              # Role business logic
│   │   ├── BindingService.cs           # Role binding logic
│   │   ├── PermissionResolver.cs       # Resolve effective permissions (CRITICAL)
│   │   ├── TokenService.cs             # JWT generation (RS256)
│   │   ├── AuditService.cs             # Audit logging
│   │   └── CacheService.cs             # Redis cache abstraction
│   ├── Authorization/
│   │   ├── Permissions.cs              # IAM's own permission constants
│   │   ├── RequirePermissionAttribute.cs
│   │   └── ServiceAccountAuthHandler.cs
│   ├── Models/
│   │   ├── Requests/
│   │   ├── Responses/
│   │   └── DTOs/
│   ├── Validators/
│   │   ├── PermissionFormatValidator.cs  # {service}.{resource}.{action}
│   │   └── RoleValidator.cs
│   ├── BackgroundServices/
│   │   ├── ExpiredBindingCleanupService.cs
│   │   └── CacheWarmupService.cs
│   ├── Middleware/
│   │   ├── StructuredLoggingMiddleware.cs
│   │   ├── DistributedTracingMiddleware.cs
│   │   └── PrometheusMetricsMiddleware.cs
│   ├── Program.cs
│   └── appsettings.json
│
├── Maliev.IAMService.Data/
│   ├── IAMDbContext.cs
│   ├── Entities/
│   │   ├── Principal.cs                # CORNERSTONE ENTITY
│   │   ├── Permission.cs
│   │   ├── Role.cs
│   │   ├── RolePermission.cs
│   │   ├── PrincipalRoleBinding.cs    # Unified for users & service accounts
│   │   └── IAMAuditLog.cs
│   ├── Repositories/
│   │   ├── IPrincipalRepository.cs     # Principal CRUD (FIRST)
│   │   ├── PrincipalRepository.cs
│   │   ├── IPermissionRepository.cs
│   │   ├── PermissionRepository.cs
│   │   ├── IRoleRepository.cs
│   │   ├── RoleRepository.cs
│   │   ├── IBindingRepository.cs
│   │   ├── BindingRepository.cs
│   │   └── IAuditRepository.cs
│   ├── Configurations/                # EF Core entity configurations
│   │   └── SnakeCaseNamingExtensions.cs
│   └── Migrations/
│
├── Maliev.IAMService.Tests/
│   ├── Unit/
│   │   ├── PrincipalServiceTests.cs
│   │   ├── PermissionResolverTests.cs
│   │   ├── PermissionServiceTests.cs
│   │   ├── RoleServiceTests.cs
│   │   ├── TokenServiceTests.cs
│   │   └── ValidatorTests.cs
│   ├── Integration/
│   │   ├── PrincipalsControllerTests.cs
│   │   ├── PermissionResolutionTests.cs  # CRITICAL TEST SUITE
│   │   ├── PermissionsControllerTests.cs
│   │   ├── RolesControllerTests.cs
│   │   ├── BindingsControllerTests.cs
│   │   ├── AuthControllerTests.cs
│   │   └── CacheInvalidationTests.cs
│   └── Testing/
│       ├── TestWebApplicationFactory.cs
│       ├── TestContainersSetup.cs      # PostgreSQL, Redis, RabbitMQ
│       └── TestDataBuilder.cs
│
└── Maliev.IAMService.Contracts/         # Shared contracts (NuGet package)
    ├── Permissions.cs                   # Permission ID constants
    ├── Events/
    │   ├── UserRoleGrantedEvent.cs
    │   ├── UserRoleRevokedEvent.cs
    │   └── RoleUpdatedEvent.cs
    └── Models/
        └── PermissionCheckRequest.cs
```

**Structure Decision**: Single .NET solution with three projects (Api, Data, Tests) plus optional Contracts library for cross-service sharing. This follows standard .NET microservice architecture with clear separation between API layer, data access, and testing. The Contracts project enables other services to reference IAM models without circular dependencies.

## Application Startup (Program.cs)

**CRITICAL**: The IAM service uses **Maliev.Aspire.ServiceDefaults** for platform-wide configurations including OpenTelemetry, health checks, database, Redis, RabbitMQ, CORS, and API versioning.

```csharp
using Maliev.IAMService.Data;
using MassTransit;

var builder = WebApplication.CreateBuilder(args);

// ===== STEP 1: Add Aspire ServiceDefaults (MUST BE FIRST) =====
builder.AddServiceDefaults();

// ===== STEP 2: Add Platform Infrastructure =====
// PostgreSQL with EF Core (via ServiceDefaults extension)
builder.AddPostgresDbContext<IAMDbContext>(
    connectionStringName: "IAMDatabase",
    enableDynamicJson: false);

// Redis distributed cache (via ServiceDefaults extension)
builder.AddRedisDistributedCache(instanceName: "iam:");

// RabbitMQ with MassTransit (via ServiceDefaults extension)
builder.AddMassTransitWithRabbitMq(configure: cfg =>
{
    // Register consumers for cache invalidation events
    cfg.AddConsumer<PermissionChangedEventConsumer>();
    cfg.AddConsumer<RoleUpdatedEventConsumer>();
});

// ===== STEP 3: Add JWT Authentication =====
// Uses RS256 public key from configuration for token validation
builder.AddJwtAuthentication();

// ===== STEP 4: Add API Features =====
// API versioning (via ServiceDefaults extension)
builder.AddDefaultApiVersioning();

// CORS (via ServiceDefaults extension)
builder.AddDefaultCors();

// OpenAPI documentation
builder.Services.AddOpenApi();

// ===== STEP 5: Add Business Services =====
builder.Services.AddControllers();
builder.Services.AddScoped<IPrincipalRepository, PrincipalRepository>();
builder.Services.AddScoped<IPermissionRepository, PermissionRepository>();
builder.Services.AddScoped<IRoleRepository, RoleRepository>();
builder.Services.AddScoped<IBindingRepository, BindingRepository>();
builder.Services.AddScoped<IAuditRepository, AuditRepository>();
builder.Services.AddScoped<PrincipalService>();
builder.Services.AddScoped<PermissionService>();
builder.Services.AddScoped<RoleService>();
builder.Services.AddScoped<BindingService>();
builder.Services.AddScoped<PermissionResolver>();
builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped<AuditService>();
builder.Services.AddScoped<CacheService>();

// Background services
builder.Services.AddHostedService<ExpiredBindingCleanupService>();

// ===== STEP 6: Add Custom Metrics =====
builder.AddServiceMeters("iam-service");

var app = builder.Build();

// ===== STEP 7: Apply Database Migrations =====
await app.MigrateDatabaseAsync<IAMDbContext>();

// ===== STEP 8: Map Endpoints =====
// Map default endpoints: /iam/liveness, /iam/readiness, /iam/metrics
app.MapDefaultEndpoints(servicePrefix: "iam");

// Map API documentation: /iam/openapi/v1.json, /iam/scalar
app.MapApiDocumentation(servicePrefix: "iam", documentName: "v1");

// Map controllers (API routes)
app.MapControllers();

app.Run();
```

**Key ServiceDefaults Integrations**:

1. **`AddServiceDefaults()`** - Configures OpenTelemetry logging, metrics, tracing, health checks, service discovery, and HTTP resilience
2. **`AddPostgresDbContext<T>()`** - Registers PostgreSQL DbContext with connection pooling, retry logic, and health checks
3. **`AddRedisDistributedCache()`** - Configures StackExchange.Redis with resilient connection settings and health checks
4. **`AddMassTransitWithRabbitMq()`** - Sets up MassTransit with RabbitMQ transport and health checks
5. **`AddJwtAuthentication()`** - Configures JWT Bearer authentication with RS256 public key validation
6. **`AddDefaultApiVersioning()`** - Enables API versioning with URL segment reader (e.g., /iam/v1/...)
7. **`AddDefaultCors()`** - Configures CORS from configuration (CORS:AllowedOrigins)
8. **`AddServiceMeters()`** - Registers custom business metrics meters with OpenTelemetry
9. **`MapDefaultEndpoints()`** - Maps /iam/liveness, /iam/readiness, /iam/metrics endpoints
10. **`MapApiDocumentation()`** - Maps /iam/openapi/v1.json and /iam/scalar UI endpoints
11. **`MigrateDatabaseAsync<T>()`** - Applies EF Core migrations with retry logic and connection waiting

**NuGet Configuration** (nuget.config):

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    <add key="maliev-private" value="https://nuget.pkg.github.com/MALIEV-Co-Ltd/index.json" />
  </packageSources>
  <packageSourceCredentials>
    <maliev-private>
      <add key="Username" value="%NUGET_USERNAME%" />
      <add key="ClearTextPassword" value="%NUGET_PASSWORD%" />
    </maliev-private>
  </packageSourceCredentials>
</configuration>
```

**CSPROJ Reference** (Maliev.IAMService.Api.csproj):

```xml
<ItemGroup>
  <!-- Platform ServiceDefaults (from private NuGet feed) -->
  <PackageReference Include="Maliev.Aspire.ServiceDefaults" Version="1.0.0" />

  <!-- Business logic dependencies -->
  <PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="8.3.0" />

  <!-- Note: Microsoft.AspNetCore.Cryptography.KeyDerivation is included in ASP.NET Core framework -->
</ItemGroup>
```

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

No violations - standard microservice architecture leveraging platform ServiceDefaults.

---

## Database Schema

### Critical: Principals Table (FIRST PRIORITY)

The `principals` table is the cornerstone of the principal-first model:

```sql
CREATE TABLE principals (
    principal_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_type VARCHAR(50) NOT NULL CHECK (principal_type IN ('user', 'service_account')),
    email VARCHAR(255) UNIQUE,
    display_name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,

    -- Links to business profile services (nullable for service accounts)
    linked_service VARCHAR(100),      -- 'CustomerService', 'EmployeeService', NULL
    linked_entity_id UUID,             -- FK to customer_id or employee_id in external service

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_principals_email ON principals(email);
CREATE INDEX idx_principals_type ON principals(principal_type);
CREATE INDEX idx_principals_linked ON principals(linked_service, linked_entity_id);
```

### Permissions

```sql
CREATE TABLE permissions (
    permission_id VARCHAR(255) PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    description TEXT,
    registered_at TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT permissions_format_check
        CHECK (permission_id ~ '^[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+$')
);

CREATE INDEX idx_permissions_service_name ON permissions(service_name);
CREATE INDEX idx_permissions_resource_type ON permissions(resource_type);
```

### Roles

```sql
CREATE TABLE roles (
    role_id VARCHAR(255) PRIMARY KEY,
    service_name VARCHAR(100),
    role_name VARCHAR(255) NOT NULL,
    description TEXT,
    is_custom BOOLEAN DEFAULT FALSE,
    created_by UUID REFERENCES principals(principal_id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT roles_service_check
        CHECK (is_custom = TRUE OR service_name IS NOT NULL)
);

CREATE INDEX idx_roles_service_name ON roles(service_name);
CREATE INDEX idx_roles_is_custom ON roles(is_custom);
```

### Role Permissions (Many-to-Many)

```sql
CREATE TABLE role_permissions (
    role_id VARCHAR(255) REFERENCES roles(role_id) ON DELETE CASCADE,
    permission_id VARCHAR(255) REFERENCES permissions(permission_id) ON DELETE CASCADE,
    added_at TIMESTAMPTZ DEFAULT NOW(),

    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_role_permissions_permission ON role_permissions(permission_id);
```

### Principal Role Bindings (Unified for Users & Service Accounts)

```sql
CREATE TABLE principal_role_bindings (
    binding_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id UUID NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    role_id VARCHAR(255) NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,

    -- Resource scoping (optional)
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),

    -- Metadata
    granted_by UUID NOT NULL REFERENCES principals(principal_id),
    granted_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,

    CONSTRAINT principal_role_bindings_unique
        UNIQUE (principal_id, role_id, COALESCE(resource_type, ''), COALESCE(resource_id, ''))
);

CREATE INDEX idx_bindings_principal ON principal_role_bindings(principal_id);
CREATE INDEX idx_bindings_role ON principal_role_bindings(role_id);
CREATE INDEX idx_bindings_expires ON principal_role_bindings(expires_at)
    WHERE expires_at IS NOT NULL;
```

### Service Account API Keys

```sql
CREATE TABLE service_account_api_keys (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id UUID NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    key_hash VARCHAR(255) NOT NULL,           -- PBKDF2 hash (via KeyDerivation.Pbkdf2)
    key_prefix VARCHAR(20) NOT NULL,           -- First 8 chars for identification
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,

    CONSTRAINT service_account_check
        CHECK EXISTS (
            SELECT 1 FROM principals p
            WHERE p.principal_id = principal_id
            AND p.principal_type = 'service_account'
        )
);

CREATE INDEX idx_api_keys_principal ON service_account_api_keys(principal_id);
CREATE INDEX idx_api_keys_prefix ON service_account_api_keys(key_prefix);
```

### Audit Logs

```sql
CREATE TABLE iam_audit_logs (
    log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action VARCHAR(50) NOT NULL,
    principal_id UUID REFERENCES principals(principal_id),
    role_id VARCHAR(255),
    permission_id VARCHAR(255),
    performed_by UUID NOT NULL REFERENCES principals(principal_id),
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    details JSONB,

    CONSTRAINT audit_action_check
        CHECK (action IN (
            'GRANT_ROLE', 'REVOKE_ROLE', 'CREATE_ROLE',
            'UPDATE_ROLE', 'DELETE_ROLE', 'REGISTER_PERMISSION',
            'CREATE_PRINCIPAL', 'UPDATE_PRINCIPAL', 'DEACTIVATE_PRINCIPAL',
            'CREATE_SERVICE_ACCOUNT', 'ROTATE_KEY', 'ISSUE_TOKEN',
            'RESOLVE_PERMISSIONS'
        ))
);

CREATE INDEX idx_audit_principal ON iam_audit_logs(principal_id);
CREATE INDEX idx_audit_action ON iam_audit_logs(action);
CREATE INDEX idx_audit_timestamp ON iam_audit_logs(timestamp DESC);
CREATE INDEX idx_audit_performed_by ON iam_audit_logs(performed_by);
CREATE INDEX idx_audit_details ON iam_audit_logs USING gin(details);
```

---

## Permission Naming Convention

Format: `{service}.{resource}.{action}`

**Examples**:
- `invoice.invoices.create`
- `invoice.invoices.read`
- `invoice.invoices.update`
- `invoice.invoices.delete`
- `invoice.invoices.approve`
- `invoice.segments.create`
- `receipt.receipts.void`
- `payment.payments.process`
- `iam.principals.create`
- `iam.roles.manage`

**Validation Regex**: `^[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+$`

---

## Redis Caching Strategy

**Keys**:
- `iam:principal:{principalId}:permissions` - Effective permissions (TTL: 5 min)
- `iam:principal:{principalId}:roles` - Role assignments (TTL: 5 min)
- `iam:role:{roleId}` - Role definition + permissions (TTL: 30 min)
- `iam:permission:{permissionId}` - Permission details (TTL: 60 min)

**Invalidation**:
- On role grant/revoke: Delete `iam:principal:{principalId}:*`
- On role update: Delete `iam:role:{roleId}` and all principal permission caches
- On permission registration: Delete `iam:permission:{permissionId}`
- Publish RabbitMQ event to invalidate across all instances

**Graceful Degradation**:
- Redis unavailable → Fallback to database queries (warn in logs)
- Message queue unavailable → Log warning, continue operation (rely on TTL for eventual consistency)

---

## RabbitMQ Events

**Exchange**: `iam-events` (topic)

**Events**:

1. **iam.principal-role-granted**
   ```json
   {
     "principalId": "uuid",
     "roleId": "invoice-admin",
     "grantedBy": "admin-uuid",
     "timestamp": "2024-01-15T10:30:00Z",
     "resourceScope": {"type": "invoice", "id": "INV-123"}
   }
   ```

2. **iam.principal-role-revoked**
   ```json
   {
     "principalId": "uuid",
     "roleId": "invoice-admin",
     "revokedBy": "admin-uuid",
     "timestamp": "2024-01-15T10:30:00Z"
   }
   ```

3. **iam.role-updated**
   ```json
   {
     "roleId": "invoice-admin",
     "updatedBy": "admin-uuid",
     "permissionsAdded": ["invoice.reports.read"],
     "permissionsRemoved": ["invoice.drafts.delete"],
     "timestamp": "2024-01-15T10:30:00Z"
   }
   ```

4. **iam.permission-registered**
   ```json
   {
     "serviceName": "InvoiceService",
     "permissionIds": ["invoice.invoices.create", "invoice.invoices.read"],
     "timestamp": "2024-01-15T10:30:00Z"
   }
   ```

---

## JWT Token Structure

**Algorithm**: RS256 (RSA with SHA-256)
**Issuer**: `https://iam.maliev.com`
**Audience**: `maliev-services` (or service-specific)
**Expiration**: Configurable (default: 60 minutes)

**Claims**:
```json
{
  "iss": "https://iam.maliev.com",
  "aud": "maliev-services",
  "sub": "principal-uuid",
  "exp": 1705329000,
  "iat": 1705325400,
  "principal_type": "user",
  "email": "user@example.com",
  "display_name": "John Doe",
  "permissions": [
    "invoice.invoices.create",
    "invoice.invoices.read",
    "invoice.invoices.update",
    "receipt.receipts.read"
  ],
  "roles": [
    "invoice-manager",
    "receipt-viewer"
  ]
}
```

**Public Key Distribution**:
- Endpoint: `GET /iam/v1/auth/.well-known/jwks.json`
- Format: JSON Web Key Set (JWKS)
- Microservices cache the public key for validation

---

## Service Registration on Startup

Each microservice implements `IHostedService` to register its permissions and roles:

```csharp
public class IAMRegistrationService : IHostedService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _config;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var client = _httpClientFactory.CreateClient("IAMService");
        var serviceAccountKey = _config["IAM:ServiceAccountKey"];

        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", serviceAccountKey);

        // Register permissions
        await client.PostAsJsonAsync("/iam/v1/permissions/register", new
        {
            ServiceName = "InvoiceService",
            Permissions = new[]
            {
                new { PermissionId = "invoice.invoices.create", ResourceType = "invoices", Action = "create", Description = "..." },
                new { PermissionId = "invoice.invoices.read", ResourceType = "invoices", Action = "read", Description = "..." }
            }
        }, cancellationToken);

        // Register predefined roles
        await client.PostAsJsonAsync("/iam/v1/roles/register", new
        {
            ServiceName = "InvoiceService",
            Roles = new[]
            {
                new
                {
                    RoleId = "invoice-admin",
                    RoleName = "Invoice Administrator",
                    Description = "Full access to invoice operations",
                    Permissions = new[] { "invoice.invoices.create", "invoice.invoices.read", "invoice.invoices.update", "invoice.invoices.delete" }
                }
            }
        }, cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
```

---

## Authorization in Microservices

```csharp
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public class RequirePermissionAttribute : AuthorizeAttribute, IAuthorizationFilter
{
    private readonly string _permission;

    public RequirePermissionAttribute(string permission)
    {
        _permission = permission;
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var user = context.HttpContext.User;

        // Check if user has permission in JWT claims
        var permissions = user.FindAll("permissions")
            .Select(c => c.Value)
            .ToList();

        if (!permissions.Contains(_permission))
        {
            context.Result = new ForbidResult();
        }
    }
}

// Usage
[RequirePermission("invoice.invoices.create")]
public async Task<IActionResult> CreateInvoice([FromBody] CreateInvoiceRequest request)
{
    // Permission already validated by attribute
    // No external IAM call needed - <10ms overhead
}
```

---

## Performance Targets

- **Permission check**: <10ms (95th percentile, cached)
- **Permission resolution**: <50ms (uncached, database query)
- **Role grant**: <100ms
- **Token issuance**: <200ms
- **Permission registration**: <2 seconds for 100+ permissions
- **Throughput**: 1000+ concurrent permission checks/second
- **Cache hit rate**: >95% for permission checks
- **Horizontal scaling**: New instance operational in <30 seconds

---

## Security Measures

1. **Authentication**: All endpoints require JWT or service account API key
2. **Authorization**: Admin operations require `iam.admin` permission
3. **API Key Security**:
   - **PBKDF2 hashing** using `Microsoft.AspNetCore.Cryptography.KeyDerivation.Pbkdf2()`
   - Algorithm: HMACSHA256
   - Iterations: 100,000 (recommended for PBKDF2)
   - Salt: 128-bit random salt per key
   - 32-character random API key generation (256-bit entropy)
   - Prefix stored for identification (first 8 characters)
   - Rotation supported
   - Example code:
     ```csharp
     using Microsoft.AspNetCore.Cryptography.KeyDerivation;

     // Generate API key
     string apiKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

     // Hash API key with PBKDF2
     byte[] salt = RandomNumberGenerator.GetBytes(128 / 8);
     string hash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
         password: apiKey,
         salt: salt,
         prf: KeyDerivationPrf.HMACSHA256,
         iterationCount: 100000,
         numBytesRequested: 256 / 8));

     // Store: hash + salt (e.g., "hash.salt" format)
     string storedHash = $"{hash}.{Convert.ToBase64String(salt)}";
     ```
4. **Rate Limiting**: Token issuance endpoints limited to 10 req/min per principal
5. **Audit Trail**: All operations logged with actor, timestamp, IP address
6. **JWT Security**:
   - RS256 asymmetric signing (2048-bit RSA keys)
   - Short expiration (60 minutes default)
   - Refresh tokens supported
7. **Input Validation**: All requests validated (FluentValidation)
8. **SQL Injection**: Protected via parameterized queries (EF Core)

---

## Testing Strategy

### Unit Tests (xUnit)
- Permission format validation logic
- Role creation/update/delete logic
- Permission resolution algorithm (CRITICAL)
- JWT token generation and signing
- Binding validation (duplicate detection, expiration)
- Cache invalidation logic

### Integration Tests (xUnit + Testcontainers)
- Full permission registration flow
- Role management CRUD operations
- Principal role binding flow
- Permission resolution accuracy (100+ test cases)
- Service account authentication
- Token issuance and validation
- Cache invalidation across instances
- RabbitMQ event publishing
- Resource-scoped permissions

### Performance Tests (NBomber or BenchmarkDotNet)
- 1000+ concurrent permission checks
- Cache hit/miss ratios
- Database query performance
- Token generation throughput
- Horizontal scaling validation

### Test Containers Setup
```csharp
public class TestWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly PostgreSqlContainer _postgresContainer;
    private readonly RedisContainer _redisContainer;
    private readonly RabbitMqContainer _rabbitMqContainer;

    public TestWebApplicationFactory()
    {
        _postgresContainer = new PostgreSqlBuilder().Build();
        _redisContainer = new RedisBuilder().Build();
        _rabbitMqContainer = new RabbitMqBuilder().Build();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureTestServices(services =>
        {
            // Replace real dependencies with test containers
            services.Configure<ConnectionStrings>(options =>
            {
                options.Database = _postgresContainer.GetConnectionString();
                options.Redis = _redisContainer.GetConnectionString();
                options.RabbitMQ = _rabbitMqContainer.GetConnectionString();
            });
        });
    }
}
```

---

## Deployment Considerations

### Environment Variables

```bash
# Database
ConnectionStrings__IAMDatabase=Host=postgres;Port=5432;Database=iam_service;...

# Caching
ConnectionStrings__Redis=redis:6379,ssl=false,abortConnect=false

# Messaging
ConnectionStrings__RabbitMQ=amqp://guest:guest@rabbitmq:5672

# JWT Configuration
JWT__Issuer=https://iam.maliev.com
JWT__Audience=maliev-services
JWT__ExpirationMinutes=60
JWT__PrivateKeyPath=/secrets/jwt-private-key.pem
JWT__PublicKeyPath=/secrets/jwt-public-key.pem

# Cache Settings
Cache__PermissionTTLMinutes=5
Cache__RoleTTLMinutes=30

# Background Jobs
BackgroundJobs__ExpiredBindingCleanupCron=0 2 * * *  # 2 AM daily

# Observability (handled by ServiceDefaults)
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317  # Optional: enables OTLP export
Logging__LogLevel__Default=Information
Logging__LogLevel__Microsoft=Warning
Logging__LogLevel__Microsoft__EntityFrameworkCore=Warning

# CORS (optional - defaults to localhost:3000)
CORS__AllowedOrigins=https://app.maliev.com,https://admin.maliev.com
```

### GitOps Deployment Pipeline

**Deployment is managed via GitOps using GitHub Actions + Kustomize + maliev-gitops repository.**

**CI/CD Workflows** (`.github/workflows/`):

1. **Development Pipeline** (`ci-develop.yml`)
   - **Trigger**: Push to `develop` branch
   - **Registry**: `asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-dev`
   - **Image Tag**: `${github.sha}`
   - **GitOps Path**: `3-apps/maliev-iam-service/overlays/development`
   - **Process**:
     1. Switch ProjectReference → PackageReference for CI build
     2. Restore, build, test .NET solution
     3. Build Docker image with NuGet secrets
     4. Push to dev artifact registry
     5. Update image tag in maliev-gitops using Kustomize
     6. Create PR to maliev-gitops for review

2. **Staging Pipeline** (`ci-staging.yml`)
   - **Trigger**: Push tags matching `release/v*`
   - **Registry**: `asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-staging`
   - **Image Tag**: `${RELEASE_VERSION}` (extracted from tag)
   - **GitOps Path**: `3-apps/maliev-iam-service/overlays/staging`
   - **Process**: Same as development, but uses release version tag

3. **Production Pipeline** (`ci-main.yml`)
   - **Trigger**: Push to `main` branch
   - **Registry**: `asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-prod`
   - **Image Tag**: `${github.sha}`
   - **GitOps Path**: `3-apps/maliev-iam-service/overlays/production`
   - **Process**: Same as development, but targets production overlay
   - **⚠️ Production deployments require PR approval before ArgoCD/Flux applies changes**

**Key Workflow Steps**:

```yaml
# Example from ci-main.yml
- name: Build and push Docker image
  run: |
    gcloud auth configure-docker asia-southeast1-docker.pkg.dev
    NUGET_USERNAME=${{ github.actor }} NUGET_PASSWORD=${{ secrets.GITOPS_PAT }} docker build \
      --secret id=nuget_username,env=NUGET_USERNAME \
      --secret id=nuget_password,env=NUGET_PASSWORD \
      -t asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-prod/maliev-iam-service:${{ github.sha }} \
      -f Maliev.IAMService.Api/Dockerfile .
    docker push asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-prod/maliev-iam-service:${{ github.sha }}

- name: Update image tag in maliev-gitops using Kustomize
  run: |
    cd maliev-gitops/3-apps/maliev-iam-service/overlays/production
    kustomize edit set image asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact/maliev-iam-service=asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-prod/maliev-iam-service:${{ github.sha }}
```

**GitOps Repository** (`MALIEV-Co-Ltd/maliev-gitops`):
- Kubernetes manifests managed via Kustomize
- Base configuration: `3-apps/maliev-iam-service/base/`
- Environment overlays: `3-apps/maliev-iam-service/overlays/{development|staging|production}/`
- Deployment, Service, Ingress, ConfigMap, Secret resources defined in GitOps repo
- ArgoCD/Flux continuously monitors and syncs cluster state

**Required Secrets** (GitHub repository secrets):
- `GITOPS_PAT`: Personal Access Token for maliev-gitops repository access
- `GCP_SA_KEY`: Google Cloud Service Account key for Artifact Registry authentication

**Deployment Approval Flow**:
1. Developer pushes to develop/main or creates release tag
2. GitHub Actions builds, tests, and pushes Docker image
3. Workflow creates PR in maliev-gitops repository
4. Team reviews and approves PR (especially for staging/production)
5. ArgoCD/Flux detects change and deploys to Kubernetes cluster

### Health Checks

**IMPORTANT**: Health checks are automatically configured by **ServiceDefaults** extensions:

- `AddPostgresDbContext<T>()` → Adds PostgreSQL health check tagged with "db", "ready"
- `AddRedisDistributedCache()` → Adds Redis health check tagged with "ready"
- `AddMassTransitWithRabbitMq()` → Adds RabbitMQ health check tagged with "ready"
- `AddServiceDefaults()` → Adds default "self" liveness check

**Endpoints** (via `MapDefaultEndpoints(servicePrefix: "iam")`):

```
GET /iam/liveness   → Always returns "Healthy" (Kubernetes liveness probe)
GET /iam/readiness  → Returns JSON health status of all dependencies (Kubernetes readiness probe)
```

**Readiness Response Example**:
```json
{
  "status": "Healthy",
  "checks": {
    "self": { "status": "Healthy", "duration": 0.5, "description": "", "exception": "" },
    "IAMDbContext": { "status": "Healthy", "duration": 12.3, "description": "", "exception": "" },
    "redis": { "status": "Healthy", "duration": 3.1, "description": "", "exception": "" },
    "rabbitmq": { "status": "Healthy", "duration": 8.7, "description": "", "exception": "" }
  },
  "totalDuration": 24.6
}
```

**No custom health check code required** - ServiceDefaults handles infrastructure health checks automatically.

### Monitoring & Observability

**IMPORTANT**: Observability is automatically configured by **ServiceDefaults**:

- **OpenTelemetry Logging** - Structured JSON logs with trace correlation
- **OpenTelemetry Metrics** - ASP.NET Core, HTTP client, and runtime metrics
- **OpenTelemetry Tracing** - Distributed tracing with W3C Trace Context propagation
- **Prometheus Endpoint** - Available at `/iam/metrics` (via `MapDefaultEndpoints`)

**Custom Business Metrics** (registered via `AddServiceMeters("iam-service")`):

```csharp
using System.Diagnostics.Metrics;

public class PermissionMetrics
{
    private readonly Meter _meter;
    private readonly Histogram<double> _permissionCheckDuration;
    private readonly Counter<long> _permissionCheckTotal;
    private readonly Counter<long> _cacheHitTotal;
    private readonly Counter<long> _cacheMissTotal;

    public PermissionMetrics()
    {
        _meter = new Meter("iam-service");
        _permissionCheckDuration = _meter.CreateHistogram<double>(
            "iam.permission_check.duration",
            "ms",
            "Permission check duration in milliseconds");
        _permissionCheckTotal = _meter.CreateCounter<long>(
            "iam.permission_check.total",
            "checks",
            "Total permission checks");
        _cacheHitTotal = _meter.CreateCounter<long>(
            "iam.cache.hit.total",
            "hits",
            "Total cache hits");
        _cacheMissTotal = _meter.CreateCounter<long>(
            "iam.cache.miss.total",
            "misses",
            "Total cache misses");
    }

    public void RecordPermissionCheck(double durationMs, bool cacheHit)
    {
        _permissionCheckDuration.Record(durationMs);
        _permissionCheckTotal.Add(1);
        if (cacheHit) _cacheHitTotal.Add(1);
        else _cacheMissTotal.Add(1);
    }
}
```

**Structured Logging** (via OpenTelemetry):
- Automatic correlation with TraceId and SpanId
- JSON format output to stdout
- Log levels configurable via `Logging__LogLevel__*` environment variables

**Distributed Tracing**:
- OTLP exporter automatically enabled when `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable is set
- Trace context propagation automatic via ServiceDefaults (W3C Trace Context)
- Custom activity sources can be added for business operations

**Configuration** (appsettings.json):
```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.EntityFrameworkCore": "Warning",
      "Microsoft.AspNetCore": "Warning"
    }
  }
}
```

**IMPORTANT - Security Policy**:
- **ONLY logging levels** are stored in appsettings.json
- **ALL configuration and secrets** (connection strings, JWT keys, CORS origins, cache settings) are passed via **environment variables**
- **NEVER store secrets in the codebase**
- Environment variables are managed via Kubernetes ConfigMap/Secrets in production

---

## Migration Path

### Phase 0: Infrastructure Setup
- Set up PostgreSQL, Redis, RabbitMQ
- Create database and apply migrations
- Configure JWT key pair generation
- Set up monitoring stack (Prometheus, Grafana, Jaeger)

### Phase 1: Core Implementation (Weeks 1-2)
1. **Principal Management** (FIRST)
   - Create `principals` table
   - Implement PrincipalService and repository
   - API endpoints for principal CRUD
   - Integration with CustomerService/EmployeeService

2. **Permission Resolution** (CRITICAL)
   - Implement PermissionResolver
   - Cache integration
   - Performance optimization
   - Unit and integration tests

3. **Permission Registration**
   - Permission validation
   - Service registration endpoint
   - Permission listing and querying

4. **Role Management**
   - Role CRUD operations
   - Role-permission associations
   - Custom role creation

### Phase 2: Bindings & Authentication (Weeks 3-4)
5. **Principal Role Bindings**
   - Grant/revoke roles
   - Resource-scoped permissions
   - Expiration handling
   - Cache invalidation

6. **Service Accounts**
   - API key generation and hashing
   - Authentication middleware
   - Key rotation

7. **JWT Token Issuance**
   - Token generation with RS256
   - Permission embedding
   - Refresh token support
   - Public key distribution

### Phase 3: Observability & Maintenance (Week 5)
8. **Audit Logging**
   - Audit trail for all operations
   - Query API with filtering
   - Log retention policies

9. **Background Services**
   - Expired binding cleanup
   - Cache warmup
   - Health checks

10. **Observability**
    - Prometheus metrics
    - Structured logging
    - Distributed tracing

### Phase 4: Testing & Documentation (Week 6)
11. **Testing**
    - 100% unit test coverage
    - Integration tests with Testcontainers
    - Performance tests
    - Security audit

12. **Documentation**
    - OpenAPI specification
    - Integration guide for microservices
    - Deployment runbook
    - Troubleshooting guide

---

## Success Criteria

1. ✅ All 49 functional requirements implemented
2. ✅ 18 success criteria met and validated
3. ✅ Permission checks complete in <10ms (95th percentile)
4. ✅ System handles 1000+ concurrent requests/second
5. ✅ 100% test coverage (unit + integration)
6. ✅ All IAM operations audited
7. ✅ Services can register permissions/roles on startup
8. ✅ JWT tokens include embedded permissions
9. ✅ Resource-scoped permissions work correctly
10. ✅ Cache invalidation propagates across instances <1 second
11. ✅ Horizontal scaling validated (add instance without downtime)
12. ✅ Prometheus metrics exposed and validated
13. ✅ Distributed tracing operational
14. ✅ OpenAPI documentation complete
15. ✅ Integration guide published

---

## Next Steps

After this plan is approved, the next phase will be:

**Phase 0: Research & Technology Validation** (`research.md`)
- Validate EF Core snake_case configuration approach
- Research RabbitMQ best practices for cache invalidation
- Evaluate Redis clustering strategies for high availability
- Research JWT key rotation strategies
- Validate Testcontainers setup for PostgreSQL 18, Redis, RabbitMQ

**Phase 1: Data Model & Contracts** (`data-model.md`, `contracts/`)
- Complete entity relationship diagrams
- Finalize OpenAPI specification with all endpoints
- Create quickstart guide for local development
- Update agent context with technology stack

**Phase 2: Task Breakdown** (`tasks.md` - generated by `/speckit.tasks`)
- Decompose implementation into atomic tasks
- Assign priorities and dependencies
- Estimate complexity
- Create sprint/iteration plan
