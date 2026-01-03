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

### Banned Libraries
- ❌ **AutoMapper**: Explicit manual mapping only.
- ❌ **FluentValidation**: Standard Data Annotations only.
- ❌ **FluentAssertions**: Standard xUnit `Assert` methods only.
- ❌ **In-memory Test DB**: All integration tests use **Testcontainers** with real PostgreSQL 18.

### Mandatory Practices
- ✅ **TreatWarningsAsErrors**: Enabled in all `.csproj` files.
- ✅ **XML Documentation**: Required on all public members.
- ✅ **No Secrets in Code**: Environment variable injection only.
- ✅ **IAM Integration**: Self-registers permissions using GCP-style naming: `{service}.{resource}.{action}`.

---

## ✨ Key Features

- **GCP-Style Permissions**: Uses `service.resource.action` hierarchy for consistent authorization.
- **Service Account Management**: Machine-to-machine identities with secure API key rotation.
- **Real-time Resolution**: Redis-backed resolution ensuring <10ms latency for auth checks.
- **Dynamic Role Binding**: Assign roles to principals with optional resource scoping.
- **Self-Registration API**: Allows microservices to register permissions during startup.

---

## 🚀 Quick Start

### Prerequisites
- .NET 10.0 SDK
- Docker Desktop
- PostgreSQL 18

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
$env:ConnectionStrings__IamDbContext="Host=localhost;Database=iam_app_db;Username=postgres;Password=YOUR_PASSWORD"
$env:ConnectionStrings__Cache="localhost:6379"
```

4. **Apply Migrations & Run**
```bash
dotnet ef database update --project Maliev.IAMService.Data
dotnet run --project Maliev.IAMService.Api
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/check` | Verify if a principal has a specific permission |
| POST | `/v1/register` | Register service permissions/roles (Startup) |
| GET | `/v1/principals` | List and manage users/service accounts |
| GET | `/v1/roles` | Manage platform and service-specific roles |

---

## 🏥 Health & Monitoring
- **Liveness**: `GET /iam/liveness`
- **Readiness**: `GET /iam/readiness`
- **Metrics**: `GET /iam/metrics`

---

## 🧪 Testing

```bash
# Run integration tests with Testcontainers
dotnet test --verbosity normal
```

---

## 📦 Deployment
- **Docker Image**: `REGION-docker.pkg.dev/PROJECT_ID/REPOSITORY/maliev-iam-service:{sha}`

---

## 📄 License
Proprietary - © 2025 MALIEV Co., Ltd. All rights reserved.
