# Feature Specification: IAM Service

**Feature Branch**: `001-iam-service`
**Created**: 2025-12-20
**Status**: Draft
**Input**: User description: "Centralized Identity and Access Management (IAM) service that provides fine-grained, Google Cloud IAM-style permission and role management for the Maliev microservices platform. This service will enable dynamic role assignments, permission checks, and comprehensive audit logging across all services."

## Clarifications

### Session 2025-12-20

- Q: When an administrator attempts to delete a role that is currently assigned to users or service accounts, what should happen? → A: Prevent deletion - Return error requiring administrator to first revoke all bindings manually
- Q: Which JWT signing algorithm should be used for token issuance? → A: RS256 - RSA signature with SHA-256 (asymmetric, recommended for microservices)
- Q: What operational observability requirements should the IAM service provide for monitoring and troubleshooting? → A: Structured logging, Prometheus metrics, distributed tracing
- Q: How should the system handle message queue failures when publishing permission change events? → A: Log and continue - Log the failure as a warning but allow IAM operation to complete (rely on cache TTL for eventual consistency)
- Q: How should the IAM service scale to handle increased load? → A: Horizontal stateless - Multiple instances sharing Redis cache, coordinated via message queue events

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Service Permission Registration (Priority: P1)

As a microservice owner, I need to register my service's permissions and predefined roles during service startup so that other services and administrators can grant appropriate access to my resources.

**Why this priority**: Without permission registration, the IAM system has no knowledge of what permissions exist across the platform. This is the foundational capability that enables all other IAM functionality.

**Independent Test**: Can be fully tested by starting a mock microservice that calls the permission registration endpoint and verifying that permissions are stored and retrievable via the list permissions API.

**Acceptance Scenarios**:

1. **Given** a microservice is starting up, **When** it sends a batch of permissions and roles to the registration endpoint, **Then** all permissions are stored with unique IDs and the service receives a success confirmation
2. **Given** permissions have been registered, **When** a service updates its permissions in a new version, **Then** the existing permissions are updated without breaking existing role assignments
3. **Given** two services attempt to register the same permission ID, **When** the second registration is attempted, **Then** the system rejects it with a conflict error

---

### User Story 2 - Grant User Access (Priority: P1)

As an administrator, I need to grant roles to users (either globally or scoped to specific resources) so that users can perform authorized actions across the platform.

**Why this priority**: Granting access is the core business value of an IAM system. Without this, users cannot access any resources, making the entire platform unusable.

**Independent Test**: Can be fully tested by creating a test user, granting them a role, and verifying that the grant appears in their role list and that permission checks return positive results.

**Acceptance Scenarios**:

1. **Given** a user exists and a role exists, **When** an administrator grants that role globally to the user, **Then** the user can perform all actions permitted by that role across all resources
2. **Given** a user exists and a role exists, **When** an administrator grants that role scoped to a specific resource (e.g., Invoice INV-123), **Then** the user can only perform permitted actions on that specific resource
3. **Given** a user already has a role, **When** an administrator attempts to grant the same role with the same scope again, **Then** the system rejects it as a duplicate binding
4. **Given** a role grant with an expiration date, **When** the expiration date passes, **Then** the user no longer has permissions from that role

---

### User Story 3 - Check User Permissions (Priority: P1)

As a microservice, I need to verify whether a user has permission to perform a specific action on a resource so that I can enforce access control without making external API calls.

**Why this priority**: Permission checking is critical for enforcing security across all services. This must be fast (< 10ms) to avoid degrading user experience.

**Independent Test**: Can be fully tested by granting a user specific permissions, then querying the permission check endpoint with various permission IDs and resource scopes to verify correct authorization decisions.

**Acceptance Scenarios**:

1. **Given** a user has a global role with permission "invoice.invoices.read", **When** a service checks if the user has that permission for any invoice, **Then** the check returns true
2. **Given** a user has a resource-scoped role for Invoice INV-123, **When** a service checks permission for Invoice INV-456, **Then** the check returns false
3. **Given** a user has multiple overlapping roles, **When** a service checks a permission, **Then** the system resolves all roles and returns the union of granted permissions
4. **Given** a user has no relevant roles, **When** a service checks a permission, **Then** the check returns false

---

### User Story 4 - Audit IAM Operations (Priority: P2)

As a security officer, I need to query a complete audit trail of all IAM operations (grants, revocations, role changes) so that I can investigate security incidents and maintain compliance.

**Why this priority**: Audit logging is critical for security and compliance, but it's not required for the system to function. It should be implemented early but can be added after core access control is working.

**Independent Test**: Can be fully tested by performing various IAM operations (grant role, revoke role, create role) and then querying the audit log API to verify all operations were recorded with correct timestamps, actors, and details.

**Acceptance Scenarios**:

1. **Given** various IAM operations have occurred, **When** a security officer queries the audit log with date filters, **Then** all operations within that time range are returned with full details
2. **Given** audit logs exist for multiple users, **When** a security officer filters by a specific user ID, **Then** only operations involving that user are returned
3. **Given** a role's permissions were modified, **When** a security officer views the audit log for that role, **Then** the before and after states are recorded

---

### User Story 5 - Manage Custom Roles (Priority: P2)

As an administrator, I need to create custom roles by combining specific permissions from across services so that I can grant precisely the access needed for specific job functions.

**Why this priority**: Custom roles enable flexible access control but are not required for basic operation. Organizations can start with predefined service roles and add custom roles as needed.

**Independent Test**: Can be fully tested by creating a custom role with specific permissions, granting it to a user, and verifying that the user gains exactly those permissions and no others.

**Acceptance Scenarios**:

1. **Given** permissions exist from multiple services, **When** an administrator creates a custom role selecting specific permissions, **Then** the role is created and can be assigned to users
2. **Given** a custom role exists, **When** an administrator updates it to add or remove permissions, **Then** all users with that role immediately gain or lose the changed permissions
3. **Given** a custom role is assigned to users or service accounts, **When** an administrator attempts to delete it, **Then** the system prevents deletion and returns an error requiring all bindings to be revoked first

---

### User Story 6 - Service Account Management (Priority: P2)

As a platform operator, I need to create service accounts with API keys and grant them roles so that microservices can authenticate and access other services programmatically.

**Why this priority**: Service accounts enable inter-service communication, which is important for microservice architectures but can initially be handled with user credentials for MVP.

**Independent Test**: Can be fully tested by creating a service account, receiving an API key, granting it a role, and using that API key to authenticate and perform permitted actions.

**Acceptance Scenarios**:

1. **Given** a platform operator creates a service account, **When** the account is created, **Then** a secure API key is generated and returned
2. **Given** a service account has an API key, **When** that key is used to authenticate, **Then** the service account receives permissions based on its assigned roles
3. **Given** a service account's API key may be compromised, **When** a platform operator rotates the key, **Then** a new key is generated and the old key is invalidated

---

### User Story 7 - JWT Token Issuance (Priority: P3)

As an authentication service, I need to issue JWT tokens that include a user's resolved permissions so that microservices can enforce access control without external calls.

**Why this priority**: JWT tokens improve performance by embedding permissions, but permission checking can initially be done via API calls. This optimization can be added after core functionality works.

**Independent Test**: Can be fully tested by requesting a JWT token for a user with known roles, decoding the token, and verifying it contains the correct permissions.

**Acceptance Scenarios**:

1. **Given** a user has been authenticated, **When** a token is issued for that user, **Then** the JWT includes all permissions resolved from their current roles
2. **Given** a user's roles change, **When** a new token is issued, **Then** the new token reflects the updated permissions
3. **Given** a token has an expiration time, **When** that time passes, **Then** the token is no longer accepted for authentication

---

### User Story 8 - Query User's Effective Permissions (Priority: P3)

As an administrator or audit tool, I need to see the complete list of effective permissions for a user (resolved from all their roles) so that I can understand what access they have.

**Why this priority**: This is useful for administration and troubleshooting but not critical for system operation. Core permission checking is more important.

**Independent Test**: Can be fully tested by granting a user multiple overlapping roles and verifying that the effective permissions list shows the union of all granted permissions without duplicates.

**Acceptance Scenarios**:

1. **Given** a user has multiple roles, **When** their effective permissions are queried, **Then** the system returns a deduplicated list of all permissions from all roles
2. **Given** a user has resource-scoped roles, **When** effective permissions are queried globally, **Then** resource-scoped permissions are clearly marked with their scope

---

### Edge Cases

- What happens when a permission is removed from a role that users already have assigned?
- How does the system handle expired role bindings during permission checks?
- What happens when a service attempts to register a permission that conflicts with another service's permission?
- How does the system handle permission checks for resources that have been deleted?
- **Role deletion with active bindings**: System prevents deletion and returns an error requiring administrator to first revoke all bindings manually
- How does the system prevent circular dependencies in resource-scoped permissions?
- **Cache staleness**: When cache is stale after permission changes, system relies on configurable TTL (default 5 minutes) for eventual consistency; message queue events trigger immediate cache invalidation when queue is available
- **Message queue failures**: System logs event publishing failures as warnings and continues with IAM operations, accepting cache TTL-based eventual consistency as acceptable trade-off
- How does the system handle bulk permission changes across many users?
- What happens when two administrators simultaneously grant conflicting roles to the same user?
- How does the system handle permission checks when the database is temporarily unavailable?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST allow microservices to register their permissions in the format `{service}.{resource}.{action}`
- **FR-002**: System MUST validate that permission IDs are unique across the entire platform
- **FR-003**: System MUST allow microservices to register predefined roles with associated permissions
- **FR-004**: System MUST allow administrators to create custom roles by selecting permissions from any registered service
- **FR-005**: System MUST allow administrators to grant roles to users globally (all resources of a type)
- **FR-006**: System MUST allow administrators to grant roles to users scoped to specific resources
- **FR-007**: System MUST support time-limited role grants with expiration dates
- **FR-008**: System MUST prevent duplicate role bindings (same user, role, and resource scope)
- **FR-009**: System MUST allow administrators to revoke role grants from users
- **FR-010**: System MUST provide an API to check if a user has a specific permission for a resource
- **FR-011**: System MUST resolve user permissions from all assigned roles (union of permissions)
- **FR-012**: System MUST return permission check results in under 10 milliseconds (95th percentile) using cached data
- **FR-013**: System MUST cache resolved user permissions with a configurable TTL (default 5 minutes)
- **FR-014**: System MUST invalidate permission caches when roles or bindings change
- **FR-015**: System MUST support creating service accounts with generated API keys
- **FR-016**: System MUST hash service account API keys before storage using bcrypt
- **FR-017**: System MUST allow granting roles to service accounts
- **FR-018**: System MUST support rotating service account API keys
- **FR-019**: System MUST log all IAM operations (grant, revoke, create, update, delete) to an audit trail
- **FR-020**: System MUST record the actor, timestamp, and full details for each audit event
- **FR-021**: System MUST allow querying audit logs by user, action type, and date range
- **FR-022**: System MUST support issuing JWT tokens that include user permissions, signed using RS256 (RSA signature with SHA-256)
- **FR-023**: System MUST support refreshing JWT tokens
- **FR-024**: System MUST use asymmetric 2048-bit RSA key pairs for JWT signing, with the public key made available to microservices for token verification
- **FR-025**: System MUST publish events via message queue when permissions change to notify other services; if event publishing fails, the system MUST log the failure as a warning and continue with the IAM operation (relying on cache TTL for eventual consistency)
- **FR-026**: System MUST automatically clean up expired role bindings daily
- **FR-027**: System MUST provide APIs to list all permissions, optionally filtered by service or resource type
- **FR-028**: System MUST provide APIs to list all roles, optionally filtered by service or custom status
- **FR-029**: System MUST provide APIs to list all role bindings for a specific user
- **FR-030**: System MUST provide APIs to get effective permissions for a user
- **FR-031**: System MUST support updating role definitions (adding or removing permissions)
- **FR-032**: System MUST support deleting roles that are not currently assigned to any users or service accounts
- **FR-033**: System MUST prevent deletion of roles that have active bindings, returning an error that lists the number of affected principals and requires manual revocation first
- **FR-034**: System MUST support hierarchical resource paths for resource-scoped permissions (e.g., organizations/org-1/projects/proj-1)
- **FR-035**: System MUST allow permission inheritance from parent resources to child resources
- **FR-036**: System MUST require authentication for all API endpoints
- **FR-037**: System MUST require the `iam.admin` permission for administrative operations
- **FR-038**: System MUST apply rate limiting to token issuance endpoints (10 requests per minute per principal) to prevent abuse
- **FR-039**: System MUST validate permission format follows the pattern `{service}.{resource}.{action}` before registration
- **FR-040**: System MUST ensure service names are unique across the platform
- **FR-041**: System MUST ensure role IDs are unique globally
- **FR-042**: All API endpoints MUST start with the prefix `/iam` for Kubernetes ingress routing (e.g., `/iam/v1/permissions/register`, `/iam/v1/users/{userId}/roles`)
- **FR-043**: System MUST emit structured logs (JSON format) for all operations including request IDs, timestamps, principal IDs, and operation outcomes
- **FR-044**: System MUST expose Prometheus-compatible metrics including permission check latency, cache hit rates, API request counts, error rates, and active role binding counts
- **FR-045**: System MUST support distributed tracing with trace context propagation for cross-service request tracking
- **FR-046**: System MUST log all authentication failures, authorization denials, and security-related events at appropriate severity levels
- **FR-047**: System MUST be designed as stateless instances that can scale horizontally by deploying multiple replicas
- **FR-048**: System MUST use shared Redis cache accessible by all service instances for permission caching
- **FR-049**: System MUST coordinate cache invalidation across all instances via message queue events to maintain consistency

### Key Entities

- **Principal**: Represents any identity in the system (user or service account). Contains a unique principal_id (UUID), principal_type (user or service_account), and timestamps. This is the universal identifier owned by IAM that all other services reference.

- **Permission**: Represents a granular action that can be performed. Contains permission_id (e.g., "invoice.invoices.create"), service_name, resource_type, action, description, and registration timestamp.

- **Role**: Represents a named collection of permissions. Contains role_id, service_name (null for custom roles), role_name, description, list of permission IDs, is_custom flag, creator ID, and timestamps.

- **Role Binding**: Represents the association between a principal and a role. Contains binding_id (UUID), principal_id, role_id, optional resource_type and resource_id for scoping, grantor principal_id, grant timestamp, and optional expiration timestamp.

- **Service Account**: Represents a non-human principal for inter-service authentication. Contains service_account_id, display_name, description, hashed API key, is_active flag, and timestamps for creation and last key rotation.

- **Audit Log Entry**: Represents a recorded IAM operation. Contains log_id (UUID), action type (e.g., GRANT_ROLE, REVOKE_ROLE), affected user/role/permission IDs, actor principal_id, timestamp, additional details (JSON object), IP address, and user agent.

- **Permission Cache Entry**: Represents cached resolved permissions for a principal. Contains principal_id, list of permission IDs, resource scope (if applicable), and expiration timestamp.

### Hierarchical Resource Paths (FR-034, FR-035)

Resource-scoped permissions support hierarchical paths using slash-separated segments:

**Format**: `{resource_type}/{resource_id}[/{child_type}/{child_id}]*`

**Examples**:
- `organizations/org-123` - Organization level
- `organizations/org-123/projects/proj-456` - Project within organization
- `organizations/org-123/projects/proj-456/invoices/inv-789` - Invoice within project

**Inheritance Rules**:
- Permissions granted at parent level automatically apply to all child resources
- Example: Role granted on `organizations/org-123` applies to all projects and invoices within that organization
- Permission checks traverse upward: Check exact resource → parent → grandparent → global
- Most specific grant wins (child overrides parent if both exist)

**Implementation Note**: Inheritance requires path parsing during permission resolution to check all ancestor paths from most specific to least specific.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Microservices can register 100+ permissions in a single API call within 2 seconds
- **SC-002**: Permission checks complete in under 10 milliseconds for 95% of requests
- **SC-003**: System supports at least 1000 concurrent permission checks per second without performance degradation
- **SC-004**: Users receive updated permissions within 5 minutes of role changes (cache TTL limit)
- **SC-005**: All IAM operations are recorded in the audit log with 100% consistency
- **SC-006**: Administrators can query audit logs spanning 90 days and receive results within 3 seconds
- **SC-007**: Service accounts can be created and receive functional API keys within 1 second
- **SC-008**: JWT tokens contain accurate permissions that reflect the user's current roles at time of issuance
- **SC-009**: Role grants and revocations take effect immediately (within cache TTL) without requiring service restarts
- **SC-010**: The system prevents 100% of duplicate role bindings (same user, role, resource scope)
- **SC-011**: Custom roles can combine permissions from any number of services without errors
- **SC-012**: Expired role bindings are automatically removed within 24 hours of expiration
- **SC-013**: API endpoints return appropriate HTTP status codes (200, 201, 400, 401, 403, 404, 409, 500) for all scenarios
- **SC-014**: Permission cache invalidation propagates to all service instances within 1 second via message queue
- **SC-015**: Resource-scoped permissions correctly restrict access to only the specified resources in 100% of test cases
- **SC-016**: All critical operations emit structured logs with correlation IDs that enable end-to-end request tracing across services
- **SC-017**: Prometheus metrics endpoints respond within 100ms and include at least 10 key performance indicators (permission check latency, cache hit rate, API throughput, error rates, etc.)
- **SC-018**: System can scale horizontally by adding new stateless instances without service disruption, with each new instance becoming operational within 30 seconds

## GCP IAM Format Implementation

### Role ID Format

The IAM service enforces Google Cloud Platform-style role identifiers:

**Format**: `roles.{service}.{role-name}`

**Examples**:
- `roles.accounting.admin` - Full admin access to Accounting service
- `roles.invoice.editor` - Read/write access to Invoice service
- `roles.payment.viewer` - Read-only access to Payment service

**Validation Rules**:
- Role IDs must start with `roles.`
- Service name must match the ServiceName field in registration requests
- Role name should use kebab-case for multi-word names (e.g., `roles.accounting.journal-entry-manager`)

**Predefined vs Custom Roles**:
- Predefined roles: Registered by services during startup via `/iam/v1/roles/register` endpoint (IsCustom = false)
- Custom roles: Created by administrators via `/iam/v1/roles` endpoint (IsCustom = true)
- Predefined roles cannot be modified or deleted once registered
- Custom roles can be updated and deleted (if no active bindings exist)

### Resource Path Format

Resource-scoped permissions use hierarchical path notation:

**Format**: `{resource-type}/{resource-id}[/{child-type}/{child-id}]*`

**Examples**:
- `projects/123` - Specific project
- `projects/123/datasets/456` - Dataset within project
- `buckets/test-bucket-789` - Storage bucket

**Wildcard Support**:
- **Single-level wildcard**: `projects/123/*` matches `projects/123/datasets` only (not grandchildren)
- **Multi-level wildcard**: `projects/123/**` matches all descendants at any depth
- **Global bindings**: `null` or omitted ResourcePath applies to all resources

**Matching Algorithm**:
1. Exact match: `projects/123` matches only `projects/123`
2. Multi-level wildcard: `projects/123/**` matches `projects/123/datasets/456/tables/789`
3. Single-level wildcard: `projects/123/*` matches `projects/123/datasets` but NOT `projects/123/datasets/456`
4. Global bindings (null path) match all resource requests

### Permission ID Format

Permissions follow the pattern: `{service}.{resource}.{action}`

**Examples**:
- `accounting.journal-entries.create` - Create journal entries
- `invoice.invoices.read` - Read invoices
- `payment.transactions.delete` - Delete payment transactions

### JWT Token Claims

Issued tokens include the following claims:

**Standard Claims**:
- `sub` - Subject (principal ID)
- `jti` - JWT ID (unique token identifier)
- `iat` - Issued at (Unix timestamp)
- `exp` - Expiration time
- `iss` - Issuer (`Maliev.IAMService`)
- `aud` - Audience (`Maliev.Services`)

**Custom Claims**:
- `principal_id` - The principal's unique identifier
- `principal_type` - Either `service_account` or `user`
- `email` - Email address (if applicable)
- `role` - Array of role IDs assigned to the principal (e.g., `["roles.accounting.admin"]`)
- `permission` - Array of permission IDs resolved from roles (e.g., `["accounting.journal-entries.create"]`)
- `resource_path` - Hierarchical resource scope (if token is resource-scoped)

**Token Signing**:
- Algorithm: RS256 (RSA signature with SHA-256)
- Key size: 2048-bit RSA keys
- Public key available at: `/iam/v1/auth/.well-known/jwks.json`

### API Endpoints

All IAM endpoints use the `/iam/v1/` prefix:

**Permission Management**:
- `POST /iam/v1/permissions/register` - Register permissions for a service
- `GET /iam/v1/permissions` - List all registered permissions

**Role Management**:
- `POST /iam/v1/roles/register` - Register predefined roles (batch)
- `POST /iam/v1/roles` - Create custom role
- `GET /iam/v1/roles` - List all roles
- `GET /iam/v1/roles/{**roleId}` - Get role by ID (catch-all route for dotted IDs)
- `PUT /iam/v1/roles/{**roleId}` - Update custom role
- `DELETE /iam/v1/roles/{**roleId}` - Delete custom role

**Principal & Binding Management**:
- `POST /iam/v1/service-accounts` - Create service account
- `GET /iam/v1/service-accounts` - List service accounts
- `GET /iam/v1/principals/{id}` - Get principal by ID
- `POST /iam/v1/principals/{id}/roles` - Grant role to principal
- `DELETE /iam/v1/principals/{id}/roles/{**roleId}` - Revoke role from principal
- `GET /iam/v1/principals/{id}/roles` - List principal's role bindings
- `GET /iam/v1/principals/{id}/effective-permissions` - Get effective permissions

**Token & Authorization**:
- `POST /iam/v1/auth/token` - Issue JWT token
- `POST /iam/v1/auth/token/refresh` - Refresh JWT token
- `POST /iam/v1/auth/resolve-permissions` - Resolve permissions for principal
- `GET /iam/v1/auth/.well-known/jwks.json` - Get JSON Web Key Set

### Database Schema

**PrincipalRoleBindings Table**:
- `Id` (Guid) - Unique binding identifier
- `PrincipalId` (Guid) - Foreign key to ServiceAccount
- `RoleId` (string, max 200) - GCP-formatted role ID
- `ResourcePath` (string, max 500, nullable) - Hierarchical resource scope
- `GrantedAt` (DateTime) - When the binding was created
- `GrantedBy` (Guid, nullable) - Who granted the role
- `ExpiresAt` (DateTime, nullable) - Optional expiration timestamp
- **Unique constraint**: `(PrincipalId, RoleId, ResourcePath)` - Prevents duplicate bindings

**Roles Table**:
- `Id` (Guid) - Internal identifier
- `RoleId` (string, max 200) - GCP-formatted role ID (e.g., `roles.accounting.admin`)
- `ServiceName` (string, max 100) - Owning service
- `Description` (string, max 500)
- `IsCustom` (bool) - True for custom roles, false for predefined
- `CreatedAt` (DateTime)

**Permissions Table**:
- `Id` (Guid) - Internal identifier
- `PermissionId` (string, max 200) - Dotted permission ID (e.g., `accounting.invoices.read`)
- `ServiceName` (string, max 100) - Owning service
- `Description` (string, max 500)
- `CreatedAt` (DateTime)

**RolePermissions Table** (Join table):
- `RoleId` (Guid) - Foreign key to Roles
- `PermissionId` (Guid) - Foreign key to Permissions

### Migration from Legacy Format

**Role ID Migration**:
- Old format: `{service}/{role-name}` (e.g., `accounting/admin`)
- New format: `roles.{service}.{role-name}` (e.g., `roles.accounting.admin`)
- Migration: `ConvertRoleIdsToGcpFormat` EF migration updates all existing role IDs

**Resource Scope Migration**:
- Old format: Separate `ResourceType` and `ResourceId` columns
- New format: Single `ResourcePath` column with hierarchical paths
- Migration: `AddResourcePathToBindings` EF migration replaces columns and updates unique constraint

**Endpoint Migration**:
- All services must use `/iam/v1/` prefix
- ServiceDefaults `IAMRegistrationService` provides base class for registration
- All DTOs updated to use `ResourcePath` instead of separate type/id fields

### Integration Guide for Services

Services should follow these steps to integrate with IAM:

1. **Define Permissions**: Create a static class listing all permissions (format: `service.resource.action`)
2. **Define Predefined Roles**: Create roles using `roles.{service}.{role-name}` format
3. **Create Registration Service**: Extend `IAMRegistrationService` from ServiceDefaults
4. **Register on Startup**: Add registration service as hosted service in Program.cs
5. **Configure IAM URL**: Set `IAM:BaseUrl` in appsettings or environment variables
6. **Use Permission Attribute**: Decorate controllers with `[Permission("service.resource.action")]`

**Reference Implementations**:
- `Maliev.AccountingService` - Complete IAM integration example
- `B:\maliev\IAM_MIGRATION_QUICK_START.md` - Step-by-step migration guide
- `B:\maliev\GCP_IAM_MIGRATION_SUMMARY.md` - Detailed migration documentation

### Testing Status

**Integration Tests**: 50 tests passing (100%)

**Test Coverage**:
- ✅ Permission registration (bulk and individual)
- ✅ Role registration (predefined and custom)
- ✅ Role CRUD operations (create, update, delete)
- ✅ Principal management (service accounts)
- ✅ Role binding (grant, revoke, list)
- ✅ Resource-scoped bindings with hierarchical paths
- ✅ Wildcard path matching (`/*` and `/**`)
- ✅ Permission resolution (global and scoped)
- ✅ JWT token issuance with embedded roles and permissions
- ✅ Token refresh with rotation
- ✅ JWKS endpoint for public key distribution
- ✅ Effective permissions queries
- ✅ Expiring role bindings
- ✅ Duplicate binding prevention

### Performance Characteristics

**Permission Resolution**:
- Cached responses: < 5ms (Redis lookup)
- Uncached responses: < 50ms (database query + cache write)
- Cache TTL: 5 minutes (configurable)

**Token Issuance**:
- New token: < 100ms (includes permission resolution + JWT signing)
- Token refresh: < 50ms (cached permission lookup)

**Role Registration**:
- Batch registration: < 2 seconds for 100+ roles
- Individual role creation: < 100ms

**Scalability**:
- Stateless design enables horizontal scaling
- Shared Redis cache across all instances
- No coordination required between instances
- Target: 1000+ permission checks/sec per instance
