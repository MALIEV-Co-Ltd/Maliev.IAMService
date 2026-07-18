using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.Interfaces;
using Maliev.IAMService.Application.Services;
using Maliev.IAMService.Domain.Entities;
using Maliev.IAMService.Infrastructure.Persistence;
using Maliev.MessagingContracts;
using Maliev.MessagingContracts.Contracts.Iam;
using MassTransit;
using Microsoft.EntityFrameworkCore;

namespace Maliev.IAMService.Api.Consumers;

/// <summary>
/// MassTransit consumer that handles permission registration requests from other services.
/// Processes registration requests asynchronously from RabbitMQ queue.
/// </summary>
public class PermissionRegistrationRequestConsumer : IConsumer<PermissionRegistrationRequest>
{
    // Serialises all concurrent UpdateAdminRoleWithNewPermissionsAsync calls so that
    // no two consumers race on the same roles.platform.owner row simultaneously.
    private static readonly SemaphoreSlim _ownerRoleSemaphore = new(1, 1);

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
                MessageType: Maliev.MessagingContracts.Contracts.Shared.MessageType.Event,
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
        await _ownerRoleSemaphore.WaitAsync(cancellationToken);
        try
        {
            _logger.LogInformation("Ensuring {RoleId} exists and has {Count} newly registered permissions", ownerRoleId, newPermissionIds.Count);

            // 1. Ensure wildcard permission exists
            var wildcardPermission = await _permissionRepository.GetByIdAsync("*", cancellationToken);
            if (wildcardPermission == null)
            {
                wildcardPermission = new Permission
                {
                    PermissionId = "*",
                    ServiceName = "platform",
                    ResourceType = "all",
                    Action = "all",
                    Description = "Wildcard permission for full access"
                };
                await _permissionRepository.CreateAsync(wildcardPermission, cancellationToken);
            }

            // 2. Ensure owner role exists
            var ownerRole = await _roleRepository.GetByIdAsync(ownerRoleId, cancellationToken);
            if (ownerRole == null)
            {
                ownerRole = new Role
                {
                    RoleId = ownerRoleId,
                    RoleName = "Platform Owner",
                    ServiceName = "platform",
                    Description = "Full administrative access",
                    IsCustom = false
                };
                await _roleRepository.CreateAsync(ownerRole, cancellationToken);

                // Reload from DB so that ownerRole is properly tracked with its persisted state
                // and RolePermissions is an accurate reflection of what exists in the database.
                ownerRole = await _roleRepository.GetByIdAsync(ownerRoleId, cancellationToken)
                    ?? throw new InvalidOperationException($"Failed to reload role '{ownerRoleId}' after creation.");
            }

            // 3. Build the set of permission IDs that are already assigned, queried directly
            // from the database to avoid stale in-memory state on the navigation collection.
            var existingPermissionIds = await _dbContext.RolePermissions
                .Where(rp => rp.RoleId == ownerRoleId)
                .Select(rp => rp.PermissionId)
                .ToHashSetAsync(cancellationToken);

            // 4. Collect all permission IDs that need to be inserted (wildcard + newly registered),
            //    excluding any that already exist — single INSERT pass, no double SaveChanges.
            var permissionsToAdd = new List<string>();

            if (!existingPermissionIds.Contains("*"))
                permissionsToAdd.Add("*");

            foreach (var permId in newPermissionIds)
            {
                if (!existingPermissionIds.Contains(permId))
                    permissionsToAdd.Add(permId);
            }

            if (permissionsToAdd.Count == 0)
            {
                _logger.LogInformation("{RoleId} already has all required permissions — nothing to update.", ownerRoleId);
                await InvalidatePermissionCacheForRoleAsync(ownerRoleId, cancellationToken);
                return;
            }

            // 5. Insert only the missing RolePermission rows directly via the DbSet so that EF
            //    does not re-examine and re-mark the entire tracked role graph. This avoids the
            //    duplicate-key violation caused by calling Roles.Update() on an already-tracked
            //    aggregate whose children have previously been saved.
            var newEntries = permissionsToAdd
                .Select(permId => new RolePermission
                {
                    RoleId = ownerRoleId,
                    PermissionId = permId
                })
                .ToList();

            await _dbContext.RolePermissions.AddRangeAsync(newEntries, cancellationToken);

            // Update the role's UpdatedAt timestamp without touching the navigation collection.
            ownerRole.UpdatedAt = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Updated {RoleId} with {Count} new permissions: {Permissions}",
                ownerRoleId, permissionsToAdd.Count, string.Join(", ", permissionsToAdd));

            // 6. Invalidate permission cache for all users with this role
            await InvalidatePermissionCacheForRoleAsync(ownerRoleId, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update admin role with new permissions");
            // Don't rethrow - permission registration should succeed even if role update fails
        }
        finally
        {
            _ownerRoleSemaphore.Release();
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
                var cacheKey = IamPermissionCacheKeys.ForPermissions(principalId);
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
