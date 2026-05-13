# Maliev IAM Service

[![Build Status](https://img.shields.io/badge/Build-Passing-success)](https://github.com/ORGANIZATION/Maliev.IAMService)
[![.NET Version](https://img.shields.io/badge/.NET-10.0-blue)](https://dotnet.microsoft.com/download/dotnet/10.0)
[![Database](https://img.shields.io/badge/Database-PostgreSQL%2018-blue)](https://www.postgresql.org/)

Centralized Identity and Access Management (IAM) service implementing a GCP-style permission model.

**Role in MALIEV Architecture**: The authoritative source for authorization across the platform. It manages principals, roles, and fine-grained permissions (`service.resource.action`). Every platform service integrates with IAM to perform authorization checks.

---

## 🏗️ Architecture & Tech Stack

- **Framework**: ASP.NET Core 10.0 (C# 13)
- **Database**: PostgreSQL 18 with Entity Framework Core 10.x
- **Distributed Cache**: Redis 7.x (High-performance permission resolution)
- **Messaging**: RabbitMQ via MassTransit
- **API Documentation**: OpenAPI 3.1 + Scalar UI
- **Observability**: OpenTelemetry (Metrics, Traces, Logging)

---

## ⚖️ Constitution Rules

This service strictly adheres to the platform development mandates:

### Banned Libraries
To maintain high performance and low complexity, the following are **NOT** used:
- ❌ **AutoMapper**: Explicit manual mapping only.
- ❌ **FluentValidation**: Standard Data Annotations (`[Required]`, `[EmailAddress]`) only.
- ❌ **FluentAssertions**: Standard xUnit `Assert` methods only.
- ❌ **In-memory Test DB**: All integration tests use **Testcontainers** with real PostgreSQL 18.

### Mandatory Practices
- ✅ **TreatWarningsAsErrors**: Enabled in all `.csproj` files.
- ✅ **XML Documentation**: Required on all public methods and properties.
- ✅ **No Secrets in Code**: All sensitive configuration injected via environment variables.
- ✅ **No Test Config in Program.cs**: Test configuration in test fixtures only.
- ✅ **IAM Integration**: Self-registers permissions with the IAM Service using GCP-style naming: `{service}.{resource}.{action}`.

---

## ✨ Key Features

- **GCP-Style Permissions**: Uses `service.resource.action` hierarchy for consistent authorization.
- **Auto-Generated Service Account Tokens**: Services generate fresh JWT tokens on-demand; production uses RS256 key pairs and the HMAC fallback is local/test only.
- **Secure Service Registration**: Protected endpoints requiring `service-account` role prevent unauthorized permission registration.
- **Real-time Resolution**: Redis-backed resolution ensuring <10ms latency for auth checks.
- **Dynamic Role Binding**: Assign roles to principals with optional resource scoping.
- **Self-Registration API**: Allows microservices to register permissions during startup with automatic authentication.

---

## 🔐 Service Account Authentication

Services authenticate with IAM using **auto-generated JWT tokens**. This prevents unauthorized entities from registering fake permissions.

### How It Works

1. Services auto-generate fresh JWT tokens on-demand during startup
2. Tokens include service identification claims and appropriate roles
3. IAM validates token signatures and role claims before allowing registration
4. Short-lived tokens (configurable expiration) improve security

### Configuration

Production services require RSA key material for token generation and validation (`Jwt:PrivateKey` for signing and `Jwt:PublicKey` for validation). `Jwt:SecurityKey` is a Development/Testing fallback only.

**Generate local fallback key:**

```bash
# OpenSSL (Recommended)
openssl rand -base64 32

# PowerShell
[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))
```

**Key Requirements:**
- At least 32 characters long
- Cryptographically random
- Never commit to version control
- Store in secure secret management system

**For detailed documentation on service account authentication and deployment, see:** `IAM_SERVICE_ACCOUNT_AUTH.md`

---

## 🚀 Quick Start

### Prerequisites
- .NET 10.0 SDK
- Docker Desktop (for infrastructure)
- PostgreSQL 18 (Alpine)

### Local Development Setup

1. **Clone the repository**
```bash
git clone https://github.com/ORGANIZATION/Maliev.IAMService.git
cd Maliev.IAMService
```

2. **Spin up Infrastructure**
```bash
docker run --name iam-db -e POSTGRES_PASSWORD=YOUR_PASSWORD -p 5432:5432 -d postgres:18-alpine
docker run --name iam-redis -p 6379:6379 -d redis:7-alpine
```

3. **Configure Environment**
```powershell
# Windows PowerShell
$env:ConnectionStrings__IamDbContext="YOUR_POSTGRES_CONNECTION_STRING"
$env:ConnectionStrings__Cache="YOUR_REDIS_CONNECTION_STRING"
```

4. **Apply Migrations & Run**
```bash
dotnet ef database update --project Maliev.IAMService.Data
dotnet run --project Maliev.IAMService.Api
```

The service will be available at `http://localhost:5000/iam`. Access the interactive documentation at `http://localhost:5000/iam/scalar`.

---

## 📡 API Endpoints

All endpoints are prefixed with `/iam/v1/`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/check-permission` | Verify if a principal has a specific permission. Requires `iam.auth.check-permission`. |
| POST | `/auth/resolve-permissions` | Resolve effective permissions. Requires `iam.auth.resolve-permissions`. |
| POST | `/permissions/register` | Register service permissions. Requires `iam.permissions.create`. |
| POST | `/roles/register` | Register service roles. Requires `iam.roles.create`. |
| GET | `/principals/bootstrap/status` | Public first-user bootstrap status only. Does not expose role or binding data. |
| GET | `/principals`, `/roles`, `/permissions` | Administrative read APIs. Require matching `iam.*.list/read` permissions. |

### Bootstrap Security

The only anonymous bootstrap endpoint is `GET /iam/v1/principals/bootstrap/status`. Role grants, revokes, role/permission/principal listing, and permission resolution/check APIs always require a platform bearer token plus the matching `RequirePermission` policy, even while the IAM database has zero or one principals. First-user elevation is handled through the authenticated `/principals/bootstrap/promote` flow.

---

## 🏥 Health & Monitoring

Standardized health probes for Kubernetes orchestration:
- **Liveness**: `GET /iam/liveness`
- **Readiness**: `GET /iam/readiness` (Checks DB and Redis connectivity)
- **Metrics**: `GET /iam/metrics` (Prometheus format)

---

## 🧪 Testing

We prioritize reliable tests over mock-heavy unit tests.

```bash
# Run all tests using Testcontainers
dotnet test --verbosity normal
```

- **Integration Tests**: Use real PostgreSQL 18 containers.
- **Contract Tests**: Ensure API stability for consumers.

---

## 📦 Deployment

Infrastructure management is handled via GitOps patterns.

- **Docker Image**: `REGION-docker.pkg.dev/PROJECT_ID/REPOSITORY/maliev-iam-service:{sha}`
- **Environments**: Development, Staging, Production

---

## 📄 License

Proprietary - © 2025 MALIEV Co., Ltd. All rights reserved.
