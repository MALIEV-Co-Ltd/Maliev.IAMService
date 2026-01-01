# Maliev IAM Service

A comprehensive Identity and Access Management (IAM) service built with .NET 10 for the Maliev platform, implementing a GCP-style IAM model with service accounts, roles, bindings, and fine-grained permissions. This service handles authentication, authorization, role-based access control (RBAC), and permission management across all Maliev microservices.

## Architecture Overview

### GCP-Style IAM Model
The Maliev IAM Service implements Google Cloud Platform's IAM model with four core concepts:

1. **Principals**: Entities that can access resources (service accounts, users)
2. **Permissions**: Atomic rights to perform specific operations (e.g., `employees.read`, `orders.write`)
3. **Roles**: Collections of permissions that can be granted together
4. **Bindings**: Associations between principals and roles, optionally scoped to specific resources

### Domain-Driven Design Layers
```
Maliev.IAMService.Api/          # Presentation layer (Controllers, DTOs)
Maliev.IAMService.Data/         # Data access layer (EF Core, Repositories)
Maliev.IAMService.Contracts/    # Shared event contracts (published as NuGet)
Maliev.IAMService.Tests/        # Integration tests with Testcontainers
```

## Features

### Core Functionality
- **Service Account Management**: Create and manage service accounts with secure API key authentication (PBKDF2-HMAC-SHA256)
- **Permission Registry**: Centralized permission registration from all microservices via `/api/iam/permissions/register`
- **Role Management**: Support for both predefined service roles and custom organizational roles
- **Role Bindings**: Flexible role-to-principal bindings with optional resource scoping and expiration dates
- **JWT Token Issuance**: RS256-signed JWT tokens with embedded permissions and roles claims
- **Permission Resolution**: Real-time permission evaluation with Redis caching (<10ms response time at 95th percentile)
- **Audit Logging**: Complete audit trail for all IAM operations stored in PostgreSQL

### Security Features
- **API Key Authentication**: PBKDF2-HMACSHA256 hashed API keys with 100,000 iterations
- **JWT Tokens**: RS256 signing with 2048-bit RSA keys
- **Refresh Tokens**: Cryptographically secure refresh tokens with single-use semantics
- **Permission Caching**: Redis-based permission caching with automatic invalidation
- **Resource-Scoped Permissions**: Fine-grained access control with resource type and ID filtering

### Technical Stack
- **Framework**: .NET 10.0 / C#
- **Database**: PostgreSQL 18 with Entity Framework Core
- **Cache**: Redis for distributed caching
- **Message Queue**: RabbitMQ with MassTransit
- **Observability**: OpenTelemetry (metrics, traces, logging)
- **API Documentation**: OpenAPI/Scalar interactive documentation

## Project Structure

```
Maliev.IAMService/
├── Maliev.IAMService.Api/          # Main API service
│   ├── Controllers/                 # REST API controllers
│   ├── Services/                    # Business logic services
│   ├── Models/                      # Request/Response DTOs
│   ├── Authorization/               # Custom authorization handlers
│   ├── Events/                      # Event consumers
│   └── Program.cs                   # Application entry point
│
├── Maliev.IAMService.Data/         # Data access layer
│   ├── Entities/                    # Entity models
│   ├── Repositories/                # Repository implementations
│   └── Migrations/                  # Database migrations
│
├── Maliev.IAMService.Contracts/    # Shared contracts (NuGet package)
│   └── Events/                      # Event definitions
│
├── Maliev.IAMService.Tests/        # Integration tests with Testcontainers
│   ├── Integration/                 # Controller integration tests
│   └── Testing/                     # Test infrastructure
│
├── .github/workflows/               # GitHub CI/CD workflows
├── .gemini/commands/                # Gemini speckit commands
├── Dockerfile                       # Multi-stage Docker build
└── nuget.config                     # NuGet package sources
```

## Getting Started

### Prerequisites

- .NET 10 SDK
- Docker (for Testcontainers - integration tests only)
- Visual Studio 2025 or VS Code (recommended)

### Running Tests

Integration tests use **Testcontainers** to automatically spin up PostgreSQL, Redis, and RabbitMQ containers. Docker must be running.

```bash
# Ensure Docker is running
docker ps

# Run all tests with code coverage
dotnet test --collect:"XPlat Code Coverage"

# Run tests in Release mode
dotnet test --configuration Release --verbosity normal
```

**Note**: Testcontainers will automatically:
- Pull required images (postgres:18-alpine, redis:7-alpine, rabbitmq:3-management-alpine)
- Start containers before tests
- Run migrations on test database
- Clean up containers after tests

### Local Development

For local development, you'll need to provide connection strings to your PostgreSQL, Redis, and RabbitMQ instances via environment variables or `appsettings.Development.json`.

```bash
# Set environment variables
export ConnectionStrings__IamDbContext="Host=localhost;Database=iam;Username=postgres;Password=postgres"
export ConnectionStrings__Redis="localhost:6379"
export RabbitMQ__Host="localhost"

# Run the service
cd Maliev.IAMService.Api
dotnet run
```

**Access the API**:
- API: http://localhost:8080
- Scalar UI: http://localhost:8080/iam/scalar
- Health: http://localhost:8080/iam/liveness
- Metrics: http://localhost:8080/iam/metrics

## API Endpoints

### Service Accounts (`/iam/v1/service-accounts`)
- `POST /` - Create service account with API key
- `GET /` - List all service accounts
- `POST /{id}/rotate-key` - Rotate API key
- `GET /{id}/effective-permissions` - Query effective permissions

### Permissions (`/iam/v1/permissions`)
- `POST /register` - Register permissions from services
- `GET /` - Get all permissions
- `GET /service/{serviceName}` - Get permissions by service
- `GET /{permissionId}` - Get specific permission

### Roles (`/iam/v1/roles`)
- `POST /register` - Register predefined roles
- `POST /custom` - Create custom role
- `GET /` - Get all roles
- `GET /service/{serviceName}` - Get roles by service
- `GET /{roleId}` - Get specific role
- `PUT /{roleId}` - Update custom role
- `DELETE /{roleId}` - Delete custom role

### Bindings (`/iam/v1/principals/{principalId}/roles`)
- `POST /` - Grant role to principal
- `GET /` - Get principal's role bindings
- `DELETE /{bindingId}` - Revoke role from principal

### Tokens (`/iam/v1/tokens`)
- `POST /issue` - Issue JWT access token
- `POST /refresh` - Refresh access token
- `GET /jwks` - Get JSON Web Key Set (for token verification)

### Authorization (`/iam/v1/auth`)
- `POST /check-permission` - Check if principal has permission
- `POST /resolve-permissions` - Resolve all permissions for principal

### Audit (`/iam/v1/audit`)
- `GET /logs` - Query audit logs

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ConnectionStrings__IamDbContext` | PostgreSQL connection string | Required |
| `ConnectionStrings__Redis` | Redis connection string | Required |
| `RabbitMQ__Host` | RabbitMQ host | localhost |
| `RabbitMQ__Username` | RabbitMQ username | guest |
| `RabbitMQ__Password` | RabbitMQ password | guest |
| `Jwt__Issuer` | JWT token issuer | Maliev.IAMService |
| `Jwt__Audience` | JWT token audience | Maliev.Services |
| `Jwt__Key` | RSA private key (base64) | Auto-generated |
| `Jwt__DefaultExpirationMinutes` | Token expiration | 60 |

## Docker

### Build Image

```bash
docker build -t maliev/iam-service:latest .
```

### Run Container

```bash
docker run -p 8080:8080 \
  -e ConnectionStrings__IamDbContext="Host=postgres;..." \
  -e ConnectionStrings__Redis="redis:6379" \
  -e RabbitMQ__Host="rabbitmq" \
  maliev/iam-service:latest
```

## CI/CD

### GitHub Actions

- **ci-develop.yml**: Build, test, lint, and security scan on develop branch
- **ci-staging.yml**: Build, test, and push Docker images on staging branch
- **ci-main.yml**: Build, test, and push Docker images on main branch

### Gemini Commands

Speckit commands available in `.gemini/commands/` for automated specification and task management.

## Performance

- **Permission Checks**: <10ms (95th percentile)
- **Throughput**: 1000+ permission checks/second
- **Cache Hit Rate**: >95% with Redis caching
- **Token Issuance**: <50ms average

## Monitoring

- **Liveness**: `/iam/liveness` - Always returns 200 OK
- **Readiness**: `/iam/readiness` - Checks database, cache, queue
- **Metrics**: `/iam/metrics` - Prometheus format metrics
- **OpenTelemetry**: Distributed tracing and metrics

## Security Best Practices

1. Rotate API keys regularly
2. Store RSA private key securely (secrets manager)
3. Use strong database passwords
4. Enable Redis authentication in production
5. Run behind HTTPS reverse proxy
6. Monitor audit logs for suspicious activity

## Messaging & Events

IAM Service publishes the following events via RabbitMQ:
- **RoleUpdatedEvent**: Published when a role's permissions are modified
- **PrincipalRoleGrantedEvent**: Published when a role is granted to a principal
- **PrincipalRoleRevokedEvent**: Published when a role is revoked from a principal
- **PermissionRegisteredEvent**: Published when new permissions are registered

**Event Contracts**: Event schemas have been added to the centralized [`Maliev.MessagingContracts`](https://github.com/MALIEV-Co-Ltd/Maliev.MessagingContracts) repository in `contracts/schemas/iam/`.

### Migration Status
✅ **Completed**:
- JSON schemas created for all IAM events
- AsyncAPI definitions registered for event channels
- Events currently published from local definitions in `Maliev.IAMService.Api/Events/`

🔄 **Next Steps** (to complete migration to centralized contracts):
1. Generate C# code from schemas in MessagingContracts repository
2. Publish updated `Maliev.MessagingContracts` NuGet package
3. Add package reference to IAM Service
4. Replace local event definitions with generated classes
5. Other services can then consume IAM events via the MessagingContracts package

## Documentation

- API Documentation: `/iam/scalar` endpoint
- Specifications: `specs/001-iam-service/`
- Architecture diagrams in `specs/` directory
- Event Contracts: `Maliev.MessagingContracts` repository

## License

Proprietary - Copyright © 2025 MALIEV Co., Ltd. All rights reserved.

## Support

For issues and feature requests, use the GitHub Issues page.
