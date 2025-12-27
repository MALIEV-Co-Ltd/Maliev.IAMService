using Maliev.IAMService.Data.Entities;
using Maliev.IAMService.Data.Repositories;
using Maliev.IAMService.Api.Models.Requests;
using Maliev.IAMService.Api.Models.Responses;
using Maliev.MessagingContracts.Generated;
using MassTransit;

namespace Maliev.IAMService.Api.Services;

/// <summary>
/// Service for managing roles (predefined and custom) with cache invalidation and event publishing.
/// Supports role registration from external services, custom role CRUD operations, and permission management.
/// Publishes RoleUpdatedEvent via MassTransit and invalidates Redis cache when roles change.
/// </summary>
public interface IRoleService
{
    /// <summary>
    /// Registers predefined roles from an external service.
    /// Role IDs must follow the format: {service}/{role-name} (e.g., "user-service/admin").
    /// Validates that all referenced permissions exist before creating roles.
    /// Duplicate roles are skipped.
    /// </summary>
    /// <param name="request">Registration request with service name and list of roles to register.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>All roles registered for the service (including previously registered ones).</returns>
    Task<IEnumerable<RoleResponse>> RegisterRolesAsync(RegisterRolesRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all roles in the system (both predefined and custom).
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collection of all role responses.</returns>
    Task<IEnumerable<RoleResponse>> GetAllAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all roles registered by a specific service.
    /// </summary>
    /// <param name="serviceName">The service name to filter roles by.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collection of roles owned by the specified service.</returns>
    Task<IEnumerable<RoleResponse>> GetByServiceAsync(string serviceName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a single role by its ID.
    /// </summary>
    /// <param name="roleId">The role ID to look up (format: service/role-name).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Role response if found; otherwise null.</returns>
    Task<RoleResponse?> GetByIdAsync(string roleId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a custom role with specified permissions.
    /// Custom roles are user-defined and can be updated or deleted (unlike predefined roles).
    /// Validates that all referenced permissions exist. Publishes audit log event.
    /// </summary>
    /// <param name="request">Custom role creation request with role ID, service name, and permission IDs.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Created role response.</returns>
    Task<RoleResponse> CreateCustomRoleAsync(CreateCustomRoleRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates a custom role by adding or removing permissions.
    /// Only custom roles can be updated (predefined roles are immutable).
    /// Invalidates role cache and all principal permission caches.
    /// Publishes RoleUpdatedEvent and audit log event.
    /// </summary>
    /// <param name="roleId">The role ID to update.</param>
    /// <param name="request">Update request with optional description, permissions to add, and permissions to remove.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Updated role response.</returns>
    Task<RoleResponse> UpdateRoleAsync(string roleId, UpdateRoleRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a custom role if it has no active bindings.
    /// Only custom roles can be deleted (predefined roles are immutable).
    /// Fails if any principals are currently assigned this role.
    /// Publishes audit log event.
    /// </summary>
    /// <param name="roleId">The role ID to delete.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task DeleteRoleAsync(string roleId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Implementation of role service with cache invalidation and event publishing.
/// Updates trigger cache invalidation for both role-specific and principal permission caches.
/// Publishes RoleUpdatedEvent via MassTransit for downstream service notification.
/// </summary>
public class RoleService : IRoleService
{
    private readonly IRoleRepository _roleRepository;
    private readonly IPermissionRepository _permissionRepository;
    private readonly ICacheService _cacheService;
    private readonly IAuditService _auditService;
    private readonly IPublishEndpoint _publishEndpoint;
    private readonly ILogger<RoleService> _logger;

    public RoleService(
        IRoleRepository roleRepository,
        IPermissionRepository permissionRepository,
        ICacheService cacheService,
        IAuditService auditService,
        IPublishEndpoint publishEndpoint,
        ILogger<RoleService> logger)
    {
        _roleRepository = roleRepository;
        _permissionRepository = permissionRepository;
        _cacheService = cacheService;
        _auditService = auditService;
        _publishEndpoint = publishEndpoint;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<IEnumerable<RoleResponse>> RegisterRolesAsync(RegisterRolesRequest request, CancellationToken cancellationToken = default)
    {
        // Validate service name
        if (string.IsNullOrWhiteSpace(request.ServiceName))
            throw new ArgumentException("Service name is required", nameof(request.ServiceName));

        // Fetch existing roles for this service once
        var existingRoles = (await _roleRepository.GetByServiceAsync(request.ServiceName, cancellationToken))
            .Select(r => r.RoleId)
            .ToHashSet();

        // Fetch all permissions mentioned in the request to validate them in bulk
        var allPermissionIdsInRequest = request.Roles.SelectMany(r => r.PermissionIds).Distinct().ToList();
        var existingPermissionIds = (await _permissionRepository.GetByIdsAsync(allPermissionIdsInRequest, cancellationToken))
            .Select(p => p.PermissionId)
            .ToHashSet();

        var rolesToCreate = new List<Role>();
        foreach (var roleDto in request.Roles)
        {
            // Validate role ID format: roles.{service}.{role-name} (GCP style)
            if (!roleDto.RoleId.StartsWith($"roles.{request.ServiceName}."))
                throw new ArgumentException($"Role ID {roleDto.RoleId} must start with roles.{request.ServiceName}. (GCP format)");

            // Check if role already exists using local cache
            if (existingRoles.Contains(roleDto.RoleId))
            {
                _logger.LogDebug("Role {RoleId} already exists, skipping", roleDto.RoleId);
                continue;
            }

            // Verify all permissions exist using local cache
            foreach (var permissionId in roleDto.PermissionIds)
            {
                if (!existingPermissionIds.Contains(permissionId))
                    throw new InvalidOperationException($"Permission {permissionId} does not exist");
            }

            // Extract role name from RoleId (format: roles.service.role-name -> role-name)
            var roleName = roleDto.RoleId.Split('.').LastOrDefault() ?? roleDto.RoleId;

            var role = new Role
            {
                RoleId = roleDto.RoleId,
                RoleName = roleName,
                ServiceName = request.ServiceName,
                Description = roleDto.Description,
                IsCustom = roleDto.IsCustom,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                RolePermissions = roleDto.PermissionIds.Select(pid => new RolePermission
                {
                    RoleId = roleDto.RoleId,
                    PermissionId = pid
                }).ToList()
            };

            rolesToCreate.Add(role);
        }

        if (rolesToCreate.Any())
        {
            foreach (var role in rolesToCreate)
            {
                await _roleRepository.CreateAsync(role, cancellationToken);
            }
            _logger.LogInformation("Registered {Count} roles for service {ServiceName}", rolesToCreate.Count, request.ServiceName);
        }

        // Return all roles for the service
        return await GetByServiceAsync(request.ServiceName, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<RoleResponse>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        var roles = await _roleRepository.GetAllAsync(cancellationToken);
        return roles.Select(MapToResponse);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<RoleResponse>> GetByServiceAsync(string serviceName, CancellationToken cancellationToken = default)
    {
        var roles = await _roleRepository.GetByServiceAsync(serviceName, cancellationToken);
        return roles.Select(MapToResponse);
    }

    /// <inheritdoc />
    public async Task<RoleResponse?> GetByIdAsync(string roleId, CancellationToken cancellationToken = default)
    {
        var role = await _roleRepository.GetByIdAsync(roleId, cancellationToken);
        return role != null ? MapToResponse(role) : null;
    }

    /// <inheritdoc />
    public async Task<RoleResponse> CreateCustomRoleAsync(CreateCustomRoleRequest request, CancellationToken cancellationToken = default)
    {
        // Verify role doesn't already exist
        var existing = await _roleRepository.GetByIdAsync(request.RoleId, cancellationToken);
        if (existing != null)
            throw new InvalidOperationException($"Role {request.RoleId} already exists");

        // Verify all permissions exist
        foreach (var permissionId in request.PermissionIds)
        {
            var permExists = await _permissionRepository.ExistsAsync(permissionId, cancellationToken);
            if (!permExists)
                throw new InvalidOperationException($"Permission {permissionId} does not exist");
        }

        // Extract role name from RoleId (format: roles.service.role-name -> role-name)
        var roleName = request.RoleId.Split('.').LastOrDefault() ?? request.RoleId;

        var role = new Role
        {
            RoleId = request.RoleId,
            RoleName = roleName,
            ServiceName = request.ServiceName,
            Description = request.Description,
            IsCustom = true,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            RolePermissions = request.PermissionIds.Select(pid => new RolePermission
            {
                RoleId = request.RoleId,
                PermissionId = pid
            }).ToList()
        };

        await _roleRepository.CreateAsync(role, cancellationToken);

        // T119: Audit logging
        await _auditService.LogAsync("CREATE_ROLE", Guid.Empty, new Dictionary<string, object>
        {
            ["role_id"] = role.RoleId,
            ["service_name"] = role.ServiceName,
            ["permission_count"] = request.PermissionIds.Count
        }, cancellationToken);

        _logger.LogInformation("Created custom role {RoleId} with {PermissionCount} permissions", role.RoleId, request.PermissionIds.Count);

        return MapToResponse(role);
    }

    /// <inheritdoc />
    public async Task<RoleResponse> UpdateRoleAsync(string roleId, UpdateRoleRequest request, CancellationToken cancellationToken = default)
    {
        var role = await _roleRepository.GetByIdAsync(roleId, cancellationToken);
        if (role == null)
            throw new InvalidOperationException($"Role {roleId} not found");

        if (!role.IsCustom)
            throw new InvalidOperationException($"Cannot update predefined role {roleId}");

        // Update description if provided
        if (!string.IsNullOrWhiteSpace(request.Description))
        {
            role.Description = request.Description;
        }

        // Add permissions
        if (request.AddPermissionIds != null && request.AddPermissionIds.Any())
        {
            foreach (var permissionId in request.AddPermissionIds)
            {
                var permExists = await _permissionRepository.ExistsAsync(permissionId, cancellationToken);
                if (!permExists)
                    throw new InvalidOperationException($"Permission {permissionId} does not exist");

                if (!role.RolePermissions.Any(rp => rp.PermissionId == permissionId))
                {
                    role.RolePermissions.Add(new RolePermission
                    {
                        RoleId = roleId,
                        PermissionId = permissionId
                    });
                }
            }
        }

        // Remove permissions
        if (request.RemovePermissionIds != null && request.RemovePermissionIds.Any())
        {
            var toRemove = role.RolePermissions
                .Where(rp => request.RemovePermissionIds.Contains(rp.PermissionId))
                .ToList();

            foreach (var rp in toRemove)
            {
                role.RolePermissions.Remove(rp);
            }
        }

        await _roleRepository.UpdateAsync(role, cancellationToken);

        // T117: Cache invalidation for role
        await _cacheService.RemoveAsync($"iam:role:{roleId}", cancellationToken);

        // T118: Invalidate all principal caches
        await _cacheService.RemoveByPrefixAsync("iam:principal:", cancellationToken);

        // T116: Publish role updated event
        var roleUpdatedEvent = new RoleUpdatedEvent(
            RoleId: roleId,
            ServiceName: role.ServiceName ?? string.Empty,
            UpdatedAt: DateTimeOffset.UtcNow
        );
        await _publishEndpoint.Publish(roleUpdatedEvent, cancellationToken);

        // T119: Audit logging
        await _auditService.LogAsync("UPDATE_ROLE", Guid.Empty, new Dictionary<string, object>
        {
            ["role_id"] = roleId,
            ["added_permissions"] = request.AddPermissionIds?.Count ?? 0,
            ["removed_permissions"] = request.RemovePermissionIds?.Count ?? 0
        }, cancellationToken);

        _logger.LogInformation("Updated role {RoleId}", roleId);

        return MapToResponse(role);
    }

    /// <inheritdoc />
    public async Task DeleteRoleAsync(string roleId, CancellationToken cancellationToken = default)
    {
        var role = await _roleRepository.GetByIdAsync(roleId, cancellationToken);
        if (role == null)
            throw new InvalidOperationException($"Role {roleId} not found");

        if (!role.IsCustom)
            throw new InvalidOperationException($"Cannot delete predefined role {roleId}");

        // T115: Check for active bindings
        var hasActiveBindings = await _roleRepository.HasActiveBindingsAsync(roleId, cancellationToken);
        if (hasActiveBindings)
            throw new InvalidOperationException($"Cannot delete role {roleId} with active bindings");

        await _roleRepository.DeleteAsync(roleId, cancellationToken);

        // T119: Audit logging
        await _auditService.LogAsync("DELETE_ROLE", Guid.Empty, new Dictionary<string, object>
        {
            ["role_id"] = roleId
        }, cancellationToken);

        _logger.LogInformation("Deleted custom role {RoleId}", roleId);
    }

    /// <summary>
    /// Maps a role entity to a role response DTO.
    /// </summary>
    /// <param name="role">The role entity to map.</param>
    /// <returns>Role response DTO with permission IDs.</returns>
    private static RoleResponse MapToResponse(Role role) => new()
    {
        RoleId = role.RoleId,
        ServiceName = role.ServiceName ?? string.Empty,
        Description = role.Description ?? string.Empty,
        IsCustom = role.IsCustom,
        PermissionIds = role.RolePermissions.Select(rp => rp.PermissionId).ToList(),
        CreatedAt = role.CreatedAt,
        UpdatedAt = role.UpdatedAt
    };
}
