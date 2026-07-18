# Tasks: IAM Service

**Input**: Design documents from `/specs/001-iam-service/`
**Prerequisites**: plan.md (required), spec.md (required for user stories)

**Tests**: Tests are NOT explicitly requested in the feature specification, so test tasks are included only for critical paths (permission resolution).

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

This is a .NET microservice project with the following structure:
- **API**: `Maliev.IAMService.Api/`
- **Data**: `Maliev.IAMService.Data/`
- **Tests**: `Maliev.IAMService.Tests/`
- **Contracts**: `Maliev.IAMService.Contracts/`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic structure

- [x] T001 Create solution structure with four projects: Api, Data, Tests, Contracts
- [x] T002 Configure NuGet package sources in nuget.config for Maliev.Aspire.ServiceDefaults
- [x] T003 [P] Add Maliev.Aspire.ServiceDefaults package reference to Maliev.IAMService.Api/Maliev.IAMService.Api.csproj
- [x] T004 [P] Add Entity Framework Core PostgreSQL packages to Maliev.IAMService.Data/Maliev.IAMService.Data.csproj
- [x] T005 [P] Add xUnit and Testcontainers packages to Maliev.IAMService.Tests/Maliev.IAMService.Tests.csproj
- [x] T006 [P] Configure appsettings.json with logging levels only (no secrets) in Maliev.IAMService.Api/appsettings.json
- [x] T007 [P] Create .gitignore for .NET projects
- [x] T008 [P] Create README.md with project overview and setup instructions

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

### Database Infrastructure

- [x] T009 Create IAMDbContext with snake_case naming convention in Maliev.IAMService.Data/IAMDbContext.cs
- [x] T010 Configure EF Core snake_case extensions in Maliev.IAMService.Data/Configurations/SnakeCaseNamingExtensions.cs
- [x] T011 Create Principal entity in Maliev.IAMService.Data/Entities/Principal.cs
- [x] T012 [P] Create Permission entity in Maliev.IAMService.Data/Entities/Permission.cs
- [x] T013 [P] Create Role entity in Maliev.IAMService.Data/Entities/Role.cs
- [x] T014 [P] Create RolePermission entity in Maliev.IAMService.Data/Entities/RolePermission.cs
- [x] T015 [P] Create PrincipalRoleBinding entity in Maliev.IAMService.Data/Entities/PrincipalRoleBinding.cs
- [x] T016 [P] Create ServiceAccountApiKey entity in Maliev.IAMService.Data/Entities/ServiceAccountApiKey.cs
- [x] T017 [P] Create IAMAuditLog entity in Maliev.IAMService.Data/Entities/IAMAuditLog.cs
- [x] T018 Create initial EF Core migration with unique constraints on permission_id, service names, and role_id in Maliev.IAMService.Data/Migrations/
- [x] T019 Configure PostgreSQL DbContext in Program.cs using AddPostgresDbContext extension

### Repository Layer

- [x] T020 Create IPrincipalRepository interface in Maliev.IAMService.Data/Repositories/IPrincipalRepository.cs
- [x] T021 Implement PrincipalRepository in Maliev.IAMService.Data/Repositories/PrincipalRepository.cs
- [x] T022 [P] Create IPermissionRepository interface in Maliev.IAMService.Data/Repositories/IPermissionRepository.cs
- [x] T023 [P] Implement PermissionRepository in Maliev.IAMService.Data/Repositories/PermissionRepository.cs
- [x] T024 [P] Create IRoleRepository interface in Maliev.IAMService.Data/Repositories/IRoleRepository.cs
- [x] T025 [P] Implement RoleRepository in Maliev.IAMService.Data/Repositories/RoleRepository.cs
- [x] T026 [P] Create IBindingRepository interface in Maliev.IAMService.Data/Repositories/IBindingRepository.cs
- [x] T027 [P] Implement BindingRepository in Maliev.IAMService.Data/Repositories/BindingRepository.cs
- [x] T028 [P] Create IAuditRepository interface in Maliev.IAMService.Data/Repositories/IAuditRepository.cs
- [x] T029 [P] Implement AuditRepository in Maliev.IAMService.Data/Repositories/IAuditRepository.cs

### Infrastructure Services

- [x] T030 Implement CacheService for Redis operations in Maliev.IAMService.Api/Services/CacheService.cs
- [x] T031 Configure Redis distributed cache in Program.cs using AddRedisDistributedCache extension
- [x] T032 Configure RabbitMQ with MassTransit in Program.cs using AddMassTransitWithRabbitMq extension
- [x] T033 Create IAM permission constants in Maliev.IAMService.Api/Authorization/Permissions.cs
- [x] T034 Configure JWT authentication in Program.cs using AddJwtAuthentication extension
- [x] T035 Implement PermissionFormatValidator in Maliev.IAMService.Api/Validators/PermissionFormatValidator.cs
- [x] T036 Configure API versioning, CORS, and OpenAPI in Program.cs
- [x] T037 Configure health checks and metrics endpoints in Program.cs using MapDefaultEndpoints
- [x] T038 [P] Implement AuditService for logging IAM operations in Maliev.IAMService.Api/Services/AuditService.cs
- [x] T039 [P] Implement PrincipalService for principal management in Maliev.IAMService.Api/Services/PrincipalService.cs
- [x] T040 [P] Configure global authentication requirement in Program.cs using RequireAuthorization policy
- [x] T041 [P] Verify ServiceDefaults observability configuration (structured logging, Prometheus, tracing) in Program.cs
- [x] T042 Create test setup with Testcontainers in Maliev.IAMService.Tests/Testing/BaseIntegrationTestFactory.cs
- [x] T043 Create TestWebApplicationFactory in Maliev.IAMService.Tests/Testing/TestWebApplicationFactory.cs

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Service Permission Registration (Priority: P1) 🎯 MVP PART 1

**Goal**: Enable microservices to register their permissions and predefined roles during startup

**Independent Test**: Start a mock microservice that calls the permission registration endpoint and verify permissions are stored and retrievable

### Implementation for User Story 1

- [x] T044 [P] [US1] Create RegisterPermissionsRequest DTO in Maliev.IAMService.Api/Models/Requests/RegisterPermissionsRequest.cs
- [x] T045 [P] [US1] Create RegisterRolesRequest DTO in Maliev.IAMService.Api/Models/Requests/RegisterRolesRequest.cs
- [x] T046 [P] [US1] Create PermissionResponse DTO in Maliev.IAMService.Api/Models/Responses/PermissionResponse.cs
- [x] T047 [P] [US1] Create RoleResponse DTO in Maliev.IAMService.Api/Models/Responses/RoleResponse.cs
- [x] T048 [US1] Implement PermissionService with registration logic in Maliev.IAMService.Api/Services/PermissionService.cs
- [x] T049 [US1] Implement RoleService with registration logic in Maliev.IAMService.Api/Services/RoleService.cs
- [x] T050 [US1] Create PermissionsController with POST /iam/v1/permissions/register endpoint in Maliev.IAMService.Api/Controllers/PermissionsController.cs
- [x] T051 [US1] Create RolesController with POST /iam/v1/roles/register endpoint in Maliev.IAMService.Api/Controllers/RolesController.cs
- [x] T052 [US1] Add GET /iam/v1/permissions endpoint for listing permissions in PermissionsController
- [x] T053 [US1] Add GET /iam/v1/roles endpoint for listing roles in RolesController
- [x] T054 [US1] Add validation for permission format {service}.{resource}.{action} and service name uniqueness in PermissionService
- [x] T055 [US1] Add duplicate permission ID conflict detection in PermissionService
- [x] T056 [US1] Add role ID uniqueness validation in RoleService
- [x] T057 [US1] Publish iam.permission-registered event to RabbitMQ in PermissionService

**Checkpoint**: At this point, microservices can register permissions and roles, and they are stored and queryable

---

## Phase 4: User Story 2 - Grant User Access (Priority: P1) 🎯 MVP PART 2

**Goal**: Enable administrators to grant roles to users (globally or resource-scoped)

**Independent Test**: Create a test user, grant them a role, verify the grant appears in their role list and permission checks return positive results

**Dependencies**: Implementation is independent, but **acceptance testing** requires User Story 3 (permission resolution) to verify granted permissions work correctly

### Implementation for User Story 2

- [x] T058 [P] [US2] Create GrantRoleRequest DTO in Maliev.IAMService.Api/Models/Requests/GrantRoleRequest.cs
- [x] T059 [P] [US2] Create RevokeRoleRequest DTO in Maliev.IAMService.Api/Models/Requests/RevokeRoleRequest.cs
- [x] T060 [P] [US2] Create RoleBindingResponse DTO in Maliev.IAMService.Api/Models/Responses/RoleBindingResponse.cs
- [x] T061 [US2] Implement BindingService with grant/revoke logic in Maliev.IAMService.Api/Services/BindingService.cs
- [x] T062 [US2] Create BindingsController with POST /iam/v1/principals/{principalId}/roles endpoint in Maliev.IAMService.Api/Controllers/BindingsController.cs
- [x] T063 [US2] Add DELETE /iam/v1/principals/{principalId}/roles/{bindingId} endpoint in BindingsController
- [x] T064 [US2] Add GET /iam/v1/principals/{principalId}/roles endpoint for listing bindings in BindingsController
- [x] T065 [US2] Implement duplicate binding detection (same principal, role, resource scope) in BindingService
- [x] T066 [US2] Implement expiration date handling for time-limited grants in BindingService
- [x] T067 [US2] Implement cache invalidation for iam:principal:{principalId}:* on grant/revoke in BindingService
- [x] T068 [US2] Publish iam.principal-role-granted event to RabbitMQ in BindingService
- [x] T069 [US2] Publish iam.principal-role-revoked event to RabbitMQ in BindingService
- [x] T070 [US2] Add audit logging for all grant/revoke operations in BindingService
- [x] T071 [US2] Implement RequirePermissionAttribute authorization filter in Maliev.IAMService.Api/Authorization/RequirePermissionAttribute.cs

**Checkpoint**: At this point, administrators can grant and revoke roles for users with global or resource-scoped access

---

## Phase 5: User Story 3 - Check User Permissions (Priority: P1) 🎯 MVP PART 3

**Goal**: Enable microservices to verify user permissions without external API calls (<10ms)

**Independent Test**: Grant a user specific permissions, then query the permission check endpoint with various permission IDs and resource scopes to verify correct authorization decisions

### Critical Tests for Permission Resolution ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [ ] T072 [P] [US3] Unit test for PermissionResolver with no roles in Maliev.IAMService.Tests/Unit/PermissionResolverTests.cs
- [ ] T073 [P] [US3] Unit test for PermissionResolver with global roles in Maliev.IAMService.Tests/Unit/PermissionResolverTests.cs
- [ ] T074 [P] [US3] Unit test for PermissionResolver with resource-scoped roles in Maliev.IAMService.Tests/Unit/PermissionResolverTests.cs
- [ ] T075 [P] [US3] Unit test for PermissionResolver with overlapping roles (union) in Maliev.IAMService.Tests/Unit/PermissionResolverTests.cs
- [ ] T076 [P] [US3] Unit test for PermissionResolver with expired bindings in Maliev.IAMService.Tests/Unit/PermissionResolverTests.cs
- [ ] T077 [P] [US3] Unit test for hierarchical resource path inheritance in Maliev.IAMService.Tests/Unit/PermissionResolverTests.cs
- [ ] T078 [P] [US3] Integration test for permission resolution accuracy in Maliev.IAMService.Tests/Integration/PermissionResolutionTests.cs

### Implementation for User Story 3

- [x] T079 [P] [US3] Create ResolvePermissionsRequest DTO in Maliev.IAMService.Api/Models/Requests/ResolvePermissionsRequest.cs
- [x] T080 [P] [US3] Create ResolvePermissionsResponse DTO in Maliev.IAMService.Api/Models/Responses/ResolvePermissionsResponse.cs
- [x] T081 [P] [US3] Create CheckPermissionRequest DTO in Maliev.IAMService.Api/Models/Requests/CheckPermissionRequest.cs
- [x] T082 [P] [US3] Create CheckPermissionResponse DTO in Maliev.IAMService.Api/Models/Responses/CheckPermissionResponse.cs
- [x] T083 [US3] Implement PermissionResolver with caching and union resolution in Maliev.IAMService.Api/Services/PermissionResolver.cs
- [x] T084 [US3] Create AuthController with POST /iam/v1/auth/resolve-permissions endpoint in Maliev.IAMService.Api/Controllers/AuthController.cs
- [x] T085 [US3] Add POST /iam/v1/auth/check-permission endpoint in AuthController
- [x] T086 [US3] Implement Redis caching for resolved permissions (TTL: 5 minutes) in PermissionResolver
- [x] T087 [US3] Implement permission resolution algorithm for global roles in PermissionResolver
- [x] T088 [US3] Implement permission resolution algorithm for resource-scoped roles in PermissionResolver
- [x] T089 [US3] Implement hierarchical resource path parsing and inheritance in PermissionResolver
- [x] T090 [US3] Implement union of permissions from multiple overlapping roles in PermissionResolver
- [x] T091 [US3] Add expired binding filtering in PermissionResolver
- [x] T092 [US3] Optimize permission check to <10ms using cached data in PermissionResolver
- [x] T093 [US3] Add Prometheus metrics for permission check latency in AuthController
- [x] T094 [US3] Add cache hit/miss metrics in PermissionResolver
- [x] T095 [US3] Create RabbitMQ consumer for iam.principal-role-granted events to invalidate cache in Maliev.IAMService.Api/Events/PermissionChangedEventConsumer.cs
- [x] T096 [US3] Create RabbitMQ consumer for iam.principal-role-revoked events to invalidate cache in PermissionChangedEventConsumer
- [x] T097 [US3] Create RabbitMQ consumer for iam.role-updated events to invalidate all principal caches in Maliev.IAMService.Api/Events/RoleUpdatedEventConsumer.cs

**Checkpoint**: At this point, microservices can resolve user permissions with <10ms latency. MVP CORE COMPLETE!

---

## Phase 6: User Story 4 - Audit IAM Operations (Priority: P2)

**Goal**: Enable security officers to query complete audit trail of all IAM operations

**Independent Test**: Perform various IAM operations (grant role, revoke role, create role) and query the audit log API to verify all operations were recorded

### Implementation for User Story 4

- [x] T098 [P] [US4] Create AuditLogQueryRequest DTO in Maliev.IAMService.Api/Models/Requests/AuditLogQueryRequest.cs
- [x] T099 [P] [US4] Create AuditLogEntryResponse DTO in Maliev.IAMService.Api/Models/Responses/AuditLogEntryResponse.cs
- [x] T100 [US4] Create AuditController with GET /iam/v1/audit/logs endpoint in Maliev.IAMService.Api/Controllers/AuditController.cs
- [x] T101 [US4] Implement date range filtering in AuditRepository
- [x] T102 [US4] Implement principal ID filtering in AuditRepository
- [x] T103 [US4] Implement action type filtering in AuditRepository
- [x] T104 [US4] Add pagination support for audit log queries in AuditController
- [x] T105 [US4] Implement JSONB details field for before/after states in AuditService
- [x] T106 [US4] Add audit log retention policy (90 days) documentation

**Checkpoint**: At this point, all IAM operations are auditable and queryable by security officers

---

## Phase 7: User Story 5 - Manage Custom Roles (Priority: P2)

**Goal**: Enable administrators to create custom roles by combining specific permissions

**Independent Test**: Create a custom role with specific permissions, grant it to a user, verify the user gains exactly those permissions

### Implementation for User Story 5

- [x] T107 [P] [US5] Create CreateCustomRoleRequest DTO in Maliev.IAMService.Api/Models/Requests/CreateCustomRoleRequest.cs
- [x] T108 [P] [US5] Create UpdateRoleRequest DTO in Maliev.IAMService.Api/Models/Requests/UpdateRoleRequest.cs
- [x] T109 [US5] Add POST /iam/v1/roles endpoint for creating custom roles in RolesController
- [x] T110 [US5] Add PUT /iam/v1/roles/{roleId} endpoint for updating roles in RolesController
- [x] T111 [US5] Add DELETE /iam/v1/roles/{roleId} endpoint for deleting roles in RolesController
- [x] T112 [US5] Implement custom role creation with permission selection in RoleService
- [x] T113 [US5] Implement role update logic (add/remove permissions) in RoleService
- [x] T114 [US5] Implement role deletion with active binding check in RoleService
- [x] T115 [US5] Add validation preventing deletion of roles with active bindings in RoleService
- [x] T116 [US5] Publish iam.role-updated event when role permissions change in RoleService
- [x] T117 [US5] Implement cache invalidation for iam:role:{roleId} on update in RoleService
- [x] T118 [US5] Invalidate all principal permission caches when role is updated in RoleService
- [x] T119 [US5] Add audit logging for custom role operations in RoleService

**Checkpoint**: At this point, administrators can create and manage custom roles with precise permission control

---

## Phase 8: User Story 6 - Service Account Management (Priority: P2)

**Goal**: Enable platform operators to create service accounts with API keys for inter-service authentication

**Independent Test**: Create a service account, receive an API key, grant it a role, use the API key to authenticate and perform permitted actions

### Implementation for User Story 6

- [x] T120 [P] [US6] Create CreateServiceAccountRequest DTO in Maliev.IAMService.Api/Models/Requests/CreateServiceAccountRequest.cs
- [x] T121 [P] [US6] Create ServiceAccountResponse DTO in Maliev.IAMService.Api/Models/Responses/ServiceAccountResponse.cs
- [x] T122 [P] [US6] Create RotateApiKeyResponse DTO in Maliev.IAMService.Api/Models/Responses/RotateApiKeyResponse.cs
- [x] T123 [US6] Extend PrincipalService with service account creation logic in Maliev.IAMService.Api/Services/PrincipalService.cs
- [x] T124 [US6] Create PrincipalsController with POST /iam/v1/service-accounts endpoint in Maliev.IAMService.Api/Controllers/PrincipalsController.cs
- [x] T125 [US6] Add POST /iam/v1/service-accounts/{id}/rotate-key endpoint in PrincipalsController
- [x] T126 [US6] Add GET /iam/v1/service-accounts endpoint for listing service accounts in PrincipalsController
- [x] T127 [US6] Implement API key generation (32 characters, 256-bit entropy) in PrincipalService
- [x] T128 [US6] Implement PBKDF2 hashing with HMACSHA256 for API keys in PrincipalService
- [x] T129 [US6] Store API key prefix (first 8 characters) for identification in PrincipalService
- [x] T130 [US6] Implement API key rotation with old key invalidation in PrincipalService
- [x] T131 [US6] Implement ServiceAccountAuthHandler for Bearer token validation in Maliev.IAMService.Api/Authorization/ServiceAccountAuthHandler.cs
- [x] T132 [US6] Add service account authentication to JWT middleware in Program.cs
- [x] T133 [US6] Add audit logging for service account operations in PrincipalService

**Checkpoint**: At this point, service accounts can authenticate with API keys and access resources based on granted roles

---

## Phase 9: User Story 7 - JWT Token Issuance (Priority: P3)

**Goal**: Issue JWT tokens with embedded permissions for microservices to enforce access control without external calls

**Independent Test**: Request a JWT token for a user with known roles, decode the token, verify it contains the correct permissions

### Implementation for User Story 7

- [x] T134 [P] [US7] Create IssueTokenRequest DTO in Maliev.IAMService.Api/Models/Requests/IssueTokenRequest.cs
- [x] T135 [P] [US7] Create TokenResponse DTO in Maliev.IAMService.Api/Models/Responses/TokenResponse.cs
- [x] T136 [P] [US7] Create RefreshTokenRequest DTO in Maliev.IAMService.Api/Models/Requests/RefreshTokenRequest.cs
- [x] T137 [US7] Implement TokenService with RS256 signing in Maliev.IAMService.Api/Services/TokenService.cs
- [x] T138 [US7] Add POST /iam/v1/auth/token endpoint in AuthController
- [x] T139 [US7] Add POST /iam/v1/auth/refresh endpoint in AuthController
- [x] T140 [US7] Add GET /iam/v1/auth/.well-known/jwks.json endpoint in AuthController
- [x] T141 [US7] Implement 2048-bit RSA key pair generation for JWT signing in TokenService
- [x] T142 [US7] Implement JWT claims with principal_id, permissions, roles in TokenService
- [x] T143 [US7] Implement token expiration (configurable, default 60 minutes) in TokenService
- [x] T144 [US7] Implement refresh token generation and validation in TokenService
- [x] T145 [US7] Implement JWKS endpoint for public key distribution in AuthController
- [x] T146 [US7] Add rate limiting (10 req/min per principal) for token issuance in AuthController
- [x] T147 [US7] Add audit logging for token issuance in TokenService
- [x] T148 [US7] Add Prometheus metrics for token generation throughput in AuthController

**Checkpoint**: At this point, JWT tokens include embedded permissions, enabling <10ms authorization checks in microservices

---

## Phase 10: User Story 8 - Query User's Effective Permissions (Priority: P3)

**Goal**: Enable administrators to see complete list of effective permissions for a user

**Independent Test**: Grant a user multiple overlapping roles, verify the effective permissions list shows the union of all permissions without duplicates

### Implementation for User Story 8

- [x] T149 [P] [US8] Create EffectivePermissionsResponse DTO in Maliev.IAMService.Api/Models/Requests/EffectivePermissionsResponse.cs
- [x] T150 [US8] Add GET /iam/v1/principals/{principalId}/effective-permissions endpoint in PrincipalsController
- [x] T151 [US8] Implement effective permissions query with deduplication in PrincipalService
- [x] T152 [US8] Add resource scope marking for resource-scoped permissions in PrincipalService
- [x] T153 [US8] Add caching for effective permissions queries in PrincipalService

**Checkpoint**: At this point, administrators can view and troubleshoot user permissions easily

---

## Phase 11: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

### Background Services

- [ ] T154 [P] Implement ExpiredBindingCleanupService (daily cron) in Maliev.IAMService.Api/BackgroundServices/ExpiredBindingCleanupService.cs
- [ ] T155 [P] Implement CacheWarmupService for startup in Maliev.IAMService.Api/BackgroundServices/CacheWarmupService.cs

### Observability

- [ ] T156 [P] Create custom Prometheus metrics for IAM operations in Maliev.IAMService.Api/Metrics/PermissionMetrics.cs
- [ ] T157 [P] Implement structured logging middleware in Maliev.IAMService.Api/Middleware/StructuredLoggingMiddleware.cs
- [ ] T158 [P] Implement distributed tracing middleware in Maliev.IAMService.Api/Middleware/DistributedTracingMiddleware.cs
- [ ] T159 [P] Configure OpenTelemetry exporters in Program.cs

### Contracts Package

- [ ] T160 [P] Create shared permission constants in Maliev.IAMService.Contracts/Permissions.cs
- [ ] T161 [P] Create event contracts in Maliev.IAMService.Contracts/Events/
- [ ] T162 [P] Package Contracts as NuGet package for other services

### Documentation & Deployment

- [ ] T163 [P] Create OpenAPI specification in specs/001-iam-service/contracts/openapi.yaml
- [ ] T164 [P] Create integration guide for microservices in docs/integration-guide.md
- [ ] T165 [P] Create deployment runbook in docs/deployment.md
- [ ] T166 [P] Create troubleshooting guide in docs/troubleshooting.md
- [x] T167 [P] Set up GitHub Actions CI/CD workflows in .github/workflows/

### Security & Performance

- [ ] T168 [P] Security audit for SQL injection, XSS, OWASP top 10
- [ ] T169 [P] Performance testing with 1000+ concurrent requests
- [ ] T170 [P] Load testing for permission resolution <10ms target
- [ ] T171 [P] Horizontal scaling validation: Deploy 2+ instances, verify cache invalidation propagates within 1 second via message queue

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3-10)**: All depend on Foundational phase completion
  - **US1 (Permission Registration)**: Can start after Foundational - No dependencies on other stories
  - **US2 (Grant Access)**: Can start after Foundational - Requires US3 for testability
  - **US3 (Check Permissions)**: Can start after Foundational - No dependencies on other stories (CRITICAL PATH)
  - **US4 (Audit)**: Can start after Foundational - No dependencies on other stories
  - **US5 (Custom Roles)**: Requires US1 (permissions must be registered to create roles)
  - **US6 (Service Accounts)**: Can start after Foundational - No dependencies on other stories
  - **US7 (JWT Tokens)**: Requires US3 (permission resolution needed for embedding)
  - **US8 (Effective Permissions)**: Requires US2 (role bindings needed to resolve permissions)
- **Polish (Phase 11)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Independent - Permission registration is foundational
- **User Story 2 (P1)**: Soft dependency on US3 for full testing, but can be implemented independently
- **User Story 3 (P1)**: Independent - Permission checking is core functionality (CRITICAL PATH)
- **User Story 4 (P2)**: Independent - Audit logging runs in parallel with operations
- **User Story 5 (P2)**: Depends on US1 - Needs registered permissions to create custom roles
- **User Story 6 (P2)**: Independent - Service accounts are separate from user management
- **User Story 7 (P3)**: Depends on US3 - Needs permission resolution to embed in tokens
- **User Story 8 (P3)**: Depends on US2 - Needs role bindings to calculate effective permissions

### Within Each User Story

- Models/DTOs before services
- Services before controllers
- Core implementation before events/caching
- Tests written FIRST for critical paths (User Story 3)

### Parallel Opportunities

- **Phase 1**: T002-T008 can run in parallel (different configuration files)
- **Phase 2 (Database)**: T012-T017 (entity creation) can run in parallel
- **Phase 2 (Repositories)**: T022-T029 (repository implementations) can run in parallel after interfaces
- **Phase 2 (Infrastructure)**: T038-T041 (services and configuration) can run in parallel
- **Within each user story**: All DTOs marked [P] can run in parallel
- **Across user stories**: US1, US3, US4, US6 can be developed in parallel after Phase 2 completes
- **Phase 11**: All polish tasks marked [P] can run in parallel

---

## Parallel Example: User Story 3 (Critical Path)

```bash
# Launch all test files for User Story 3 together (T072-T078):
Task: "Unit test for PermissionResolver with no roles in Maliev.IAMService.Tests/Unit/PermissionResolverTests.cs"
Task: "Unit test for PermissionResolver with global roles in Maliev.IAMService.Tests/Unit/PermissionResolverTests.cs"
Task: "Unit test for PermissionResolver with resource-scoped roles in Maliev.IAMService.Tests/Unit/PermissionResolverTests.cs"
Task: "Unit test for PermissionResolver with overlapping roles in Maliev.IAMService.Tests/Unit/PermissionResolverTests.cs"
Task: "Unit test for PermissionResolver with expired bindings in Maliev.IAMService.Tests/Unit/PermissionResolverTests.cs"
Task: "Unit test for hierarchical resource path inheritance in Maliev.IAMService.Tests/Unit/PermissionResolverTests.cs"
Task: "Integration test for permission resolution in Maliev.IAMService.Tests/Integration/PermissionResolutionTests.cs"

# Launch all DTOs for User Story 3 together (T079-T082):
Task: "Create ResolvePermissionsRequest DTO in Maliev.IAMService.Api/Models/Requests/ResolvePermissionsRequest.cs"
Task: "Create ResolvePermissionsResponse DTO in Maliev.IAMService.Api/Models/Responses/ResolvePermissionsResponse.cs"
Task: "Create CheckPermissionRequest DTO in Maliev.IAMService.Api/Models/Requests/CheckPermissionRequest.cs"
Task: "Create CheckPermissionResponse DTO in Maliev.IAMService.Api/Models/Responses/CheckPermissionResponse.cs"
```

---

## Implementation Strategy

### MVP First (User Stories 1, 2, 3 Only)

1. Complete Phase 1: Setup (T001-T008)
2. Complete Phase 2: Foundational (T009-T043) - CRITICAL - blocks all stories
3. Complete Phase 3: User Story 1 - Permission Registration (T044-T057)
4. Complete Phase 5: User Story 3 - Permission Checking (T072-T097) - CRITICAL PATH
5. Complete Phase 4: User Story 2 - Grant Access (T058-T071)
6. **STOP and VALIDATE**: Test the complete flow:
   - Register permissions from a mock service
   - Grant roles to a test user
   - Resolve permissions and verify <10ms latency (95th percentile)
   - Test hierarchical resource path inheritance
7. Deploy/demo if ready

**MVP Success Criteria**:
- ✅ Microservices can register permissions and roles
- ✅ Administrators can grant roles to users
- ✅ Permission checks complete in <10ms (95th percentile) with caching
- ✅ System handles 1000+ concurrent permission checks/second
- ✅ Hierarchical resource permissions work correctly

### Incremental Delivery (Post-MVP)

1. Add User Story 4 (Audit Logging) → Deploy/Demo (Security & Compliance)
2. Add User Story 5 (Custom Roles) → Deploy/Demo (Flexible Access Control)
3. Add User Story 6 (Service Accounts) → Deploy/Demo (Inter-Service Auth)
4. Add User Story 7 (JWT Tokens) → Deploy/Demo (Embedded Permissions)
5. Add User Story 8 (Effective Permissions) → Deploy/Demo (Admin Tooling)
6. Complete Phase 11 (Polish) → Production Ready

### Parallel Team Strategy

With multiple developers:

1. **Team completes Setup + Foundational together** (Phase 1-2)
2. Once Foundational is done:
   - **Developer A**: User Story 1 (Permission Registration)
   - **Developer B**: User Story 3 (Permission Checking) - CRITICAL PATH
   - **Developer C**: User Story 4 (Audit Logging)
3. After MVP core (US1, US2, US3):
   - **Developer A**: User Story 5 (Custom Roles)
   - **Developer B**: User Story 6 (Service Accounts)
   - **Developer C**: User Story 7 (JWT Tokens)
4. Final integration:
   - **Developer A**: User Story 8 (Effective Permissions)
   - **Developer B**: Background Services (Phase 11)
   - **Developer C**: Documentation & Deployment (Phase 11)

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- User Story 3 is CRITICAL PATH - prioritize permission resolution accuracy and performance
- Verify tests FAIL before implementing (US3 tests are mandatory)
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- **Principal-First Model**: IAM owns all principals; Customer/Employee services reference principal_id
- **Performance Target**: <10ms permission checks (95th percentile)
- **Security**: PBKDF2 for API keys, RS256 for JWT, no secrets in appsettings.json
- Avoid: vague tasks, same file conflicts, cross-story dependencies that break independence