using Maliev.IAMService.Api.Models.Requests;
using Maliev.IAMService.Api.Services;
using Maliev.IAMService.Data;
using Maliev.IAMService.Data.Entities;
using Maliev.IAMService.Data.Repositories;
using Maliev.MessagingContracts.Generated;
using MassTransit;
using Microsoft.EntityFrameworkCore;

namespace Maliev.IAMService.Api.Consumers;

/// <summary>
/// MassTransit consumer that handles permission registration requests from other services.
/// Processes registration requests asynchronously from RabbitMQ queue.
/// </summary>
public class PermissionRegistrationRequestConsumer : IConsumer<PermissionRegistrationRequest>
{
    private readonly IPermissionService _permissionService;
    private readonly IRoleService _roleService;
    private readonly IPublishEndpoint _publishEndpoint;
    private readonly ILogger<PermissionRegistrationRequestConsumer> _logger;
    private readonly IRoleRepository _roleRepository;
    private readonly IPermissionRepository _permissionRepository;
    private readonly ICacheService _cacheService;
    private readonly IAMDbContext _dbContext;

    /// <summary>
    /// Initializes a new instance of the PermissionRegistrationRequestConsumer.
    /// </summary>
    /// <param name="permissionService">Service for registering permissions.</param>
    /// <param name="roleService">Service for registering roles.</param>
    /// <param name="publishEndpoint">MassTransit endpoint for publishing completion events.</param>
    /// <param name="logger">Logger instance.</param>
    /// <param name="roleRepository">Repository for role operations.</param>
    /// <param name="permissionRepository">Repository for permission operations.</param>
    /// <param name="cacheService">Cache service for invalidating permission caches.</param>
    /// <param name="dbContext">Database context for querying bindings.</param>
    public PermissionRegistrationRequestConsumer(
        IPermissionService permissionService,
        IRoleService roleService,
        IPublishEndpoint publishEndpoint,
        ILogger<PermissionRegistrationRequestConsumer> logger,
        IRoleRepository roleRepository,
        IPermissionRepository permissionRepository,
        ICacheService cacheService,
        IAMDbContext dbContext)
    {
        _permissionService = permissionService;
        _roleService = roleService;
        _publishEndpoint = publishEndpoint;
        _logger = logger;
        _roleRepository = roleRepository;
        _permissionRepository = permissionRepository;
        _cacheService = cacheService;
        _dbContext = dbContext;
    }

    /// <summary>
    /// Consumes a permission registration request and registers permissions/roles with the IAM service.
    /// </summary>
    /// <param name="context">The consume context containing the message.</param>
    public async Task Consume(ConsumeContext<PermissionRegistrationRequest> context)
    {
        var request = context.Message;
        _logger.LogInformation(
            "Processing IAM registration request for {ServiceName}: {PermissionCount} permissions, {RoleCount} roles",
            request.ServiceName, request.Permissions.Count, request.Roles.Count);

        try
        {
            // Register permissions
            if (request.Permissions.Any())
            {
                var permissionRequest = new RegisterPermissionsRequest
                {
                    ServiceName = request.ServiceName,
                    Permissions = request.Permissions
                        .Select(p => new PermissionDto
                        {
                            PermissionId = p.PermissionId,
                            Description = p.Description ?? string.Empty
                        })
                        .ToList()
                };

                await _permissionService.RegisterPermissionsAsync(permissionRequest, context.CancellationToken);

                // Update roles.iam.admin to include newly registered permissions
                await UpdateAdminRoleWithNewPermissionsAsync(request.Permissions.Select(p => p.PermissionId).ToList(), context.CancellationToken);
            }

            // Register roles
            if (request.Roles.Any())
            {
                var roleRequest = new RegisterRolesRequest
                {
                    ServiceName = request.ServiceName,
                    Roles = request.Roles
                        .Select(r => new RoleDto
                        {
                            RoleId = r.RoleId,
                            Description = r.Description ?? string.Empty,
                            PermissionIds = r.PermissionIds.ToList()
                        })
                        .ToList()
                };

                await _roleService.RegisterRolesAsync(roleRequest, context.CancellationToken);
            }

            _logger.LogInformation(
                "Successfully processed IAM registration for {ServiceName}",
                request.ServiceName);

            // Publish completion event for monitoring/debugging
            await _publishEndpoint.Publish(new PermissionRegistrationCompleted(
                MessageId: Guid.NewGuid(),
                MessageName: nameof(PermissionRegistrationCompleted),
                MessageType: MessageType.Event,
                MessageVersion: "1.0.0",
                PublishedBy: "iam",
                ConsumedBy: [],
                CorrelationId: context.CorrelationId ?? Guid.NewGuid(),
                CausationId: context.MessageId,
                OccurredAtUtc: DateTimeOffset.UtcNow,
                IsPublic: false,
                ServiceName: request.ServiceName,
                PermissionCount: request.Permissions.Count,
                RoleCount: request.Roles.Count,
                RegisteredAt: DateTimeOffset.UtcNow
            ), context.CancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to process IAM registration for {ServiceName}", request.ServiceName);
            throw; // Rethrow to trigger MassTransit retry/error handling
        }
    }

    /// <summary>
    /// Updates the roles.platform.owner role to include newly registered permissions.
    /// This ensures the owner role always has ALL permissions across all services.
    /// </summary>
    /// <param name="newPermissionIds">List of newly registered permission IDs.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task UpdateAdminRoleWithNewPermissionsAsync(List<string> newPermissionIds, CancellationToken cancellationToken)
    {
        const string ownerRoleId = "roles.platform.owner";

        try
        {
            _logger.LogInformation("Attempting to update {RoleId} with {Count} newly registered permissions", ownerRoleId, newPermissionIds.Count);

            // Check if owner role exists
            var ownerRole = await _roleRepository.GetByIdAsync(ownerRoleId, cancellationToken);
            if (ownerRole == null)
            {
                _logger.LogWarning("Owner role {RoleId} does not exist yet, skipping permission sync", ownerRoleId);
                return;
            }

            _logger.LogInformation("Owner role {RoleId} found with {ExistingCount} existing permissions", ownerRoleId, ownerRole.RolePermissions.Count);

            // Get the actual permission entities
            var allPermissions = await _permissionRepository.GetAllAsync(cancellationToken);
            var newPermissions = allPermissions.Where(p => newPermissionIds.Contains(p.PermissionId)).ToList();

            _logger.LogInformation("Found {NewPermissionsCount} new permissions in database out of {RequestedCount} requested",
                newPermissions.Count, newPermissionIds.Count);

            if (!newPermissions.Any())
            {
                _logger.LogWarning("No new permissions found to add to {RoleId}", ownerRoleId);
                return;
            }

            // Get existing permission IDs in the role
            var existingPermissionIds = ownerRole.RolePermissions.Select(rp => rp.PermissionId).ToHashSet();

            // Add only permissions that don't already exist
            var permissionsToAdd = newPermissions.Where(p => !existingPermissionIds.Contains(p.PermissionId)).ToList();

            _logger.LogInformation("Permissions to add: {Count}. New: [{NewPerms}], Already exist: {ExistingCount}",
                permissionsToAdd.Count,
                string.Join(", ", permissionsToAdd.Select(p => p.PermissionId)),
                newPermissions.Count - permissionsToAdd.Count);

            if (!permissionsToAdd.Any())
            {
                _logger.LogInformation("All {Count} new permissions already exist in {RoleId}", newPermissions.Count, ownerRoleId);
                return;
            }

            // Add new permissions to the role
            foreach (var permission in permissionsToAdd)
            {
                ownerRole.RolePermissions.Add(new RolePermission
                {
                    RoleId = ownerRoleId,
                    PermissionId = permission.PermissionId
                });
            }

            ownerRole.UpdatedAt = DateTime.UtcNow;
            await _roleRepository.UpdateAsync(ownerRole, cancellationToken);

            _logger.LogInformation(
                "Updated {RoleId} with {Count} new permissions: {Permissions}",
                ownerRoleId, permissionsToAdd.Count, string.Join(", ", permissionsToAdd.Select(p => p.PermissionId)));

            // Invalidate permission cache for all users with this role
            await InvalidatePermissionCacheForRoleAsync(ownerRoleId, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update admin role with new permissions");
            // Don't rethrow - permission registration should succeed even if role update fails
        }
    }

    /// <summary>
    /// Invalidates the permission cache for all principals that have the specified role.
    /// This ensures users get fresh permissions on their next request.
    /// </summary>
    /// <param name="roleId">The role ID whose bindings should have cache invalidated.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task InvalidatePermissionCacheForRoleAsync(string roleId, CancellationToken cancellationToken)
    {
        try
        {
            // Get all bindings for this role using DbContext
            var principalIds = await _dbContext.PrincipalRoleBindings
                .Where(b => b.RoleId == roleId)
                .Select(b => b.PrincipalId)
                .Distinct()
                .ToListAsync(cancellationToken);

            _logger.LogInformation("Invalidating permission cache for {Count} principals with role {RoleId}",
                principalIds.Count, roleId);

            // Invalidate cache for each principal
            foreach (var principalId in principalIds)
            {
                var cacheKey = $"iam:principal:{principalId}:permissions";
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
            }

            _logger.LogInformation("Successfully invalidated permission cache for {Count} principals", principalIds.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to invalidate permission cache for role {RoleId}", roleId);
            // Don't rethrow - cache invalidation failure shouldn't fail permission registration
        }
    }
}
