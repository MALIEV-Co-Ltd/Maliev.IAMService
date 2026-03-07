using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Application.Interfaces;
using Maliev.IAMService.Application.Validators;
using Maliev.IAMService.Domain.Entities;
using Maliev.MessagingContracts;
using Maliev.MessagingContracts.Contracts.Iam;
using MassTransit;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace Maliev.IAMService.Application.Services;

/// <summary>
/// Service for managing permissions and their registration from external services.
/// Validates permission format (service.resource.action) and publishes events via MassTransit.
/// Ensures permissions are unique and properly scoped to their owning service.
/// </summary>
public interface IPermissionService
{
    /// <summary>
    /// Registers permissions from an external service with format validation.
    /// Permission IDs must follow the format: {service}.{resource}.{action}.
    /// Duplicate permissions are skipped. Successfully registered permissions trigger PermissionRegisteredEvent.
    /// </summary>
    /// <param name="request">Registration request with service name and list of permissions to register.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>All permissions registered for the service (including previously registered ones).</returns>
    Task<IEnumerable<PermissionResponse>> RegisterPermissionsAsync(RegisterPermissionsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all permissions registered in the system across all services.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collection of all permission responses.</returns>
    Task<IEnumerable<PermissionResponse>> GetAllAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all permissions registered by a specific service.
    /// </summary>
    /// <param name="serviceName">The service name to filter permissions by.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collection of permissions owned by the specified service.</returns>
    Task<IEnumerable<PermissionResponse>> GetByServiceAsync(string serviceName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a single permission by its unique identifier.
    /// </summary>
    /// <param name="permissionId">The unique permission identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Permission response if found; otherwise null.</returns>
    Task<PermissionResponse?> GetByIdAsync(string permissionId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Implementation of permission service with format validation and event publishing.
/// Uses PermissionFormatValidator to ensure {service}.{resource}.{action} format.
/// Publishes PermissionRegisteredEvent via MassTransit for each newly registered permission.
/// </summary>
public class PermissionService : IPermissionService
{
    private readonly IPermissionRepository _permissionRepository;
    private readonly IPublishEndpoint _publishEndpoint;
    private readonly ILogger<PermissionService> _logger;
    private static readonly SemaphoreSlim _registrationSemaphore = new(20, 20);
    private static readonly ConcurrentDictionary<string, byte> _recentlyRegisteredServices = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="PermissionService"/> class.
    /// </summary>
    /// <param name="permissionRepository">Repository for permission CRUD operations.</param>
    /// <param name="publishEndpoint">MassTransit endpoint for publishing events.</param>
    /// <param name="logger">Logger instance.</param>
    public PermissionService(IPermissionRepository permissionRepository, IPublishEndpoint publishEndpoint, ILogger<PermissionService> logger)
    {
        _permissionRepository = permissionRepository;
        _publishEndpoint = publishEndpoint;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<IEnumerable<PermissionResponse>> RegisterPermissionsAsync(RegisterPermissionsRequest request, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.ServiceName))
            throw new ArgumentException("Service name is required", nameof(request.ServiceName));

        await _registrationSemaphore.WaitAsync(cancellationToken);
        try
        {
            var existingPermissionsFromDb = (await _permissionRepository.GetByServiceAsync(request.ServiceName, cancellationToken)).ToList();
            var existingPermissionsDict = existingPermissionsFromDb.ToDictionary(p => p.PermissionId);

            var permissionsToCreate = new List<Permission>();
            var permissionsToUpdate = new List<Permission>();

            foreach (var permDto in request.Permissions.DistinctBy(p => p.PermissionId))
            {
                if (!PermissionFormatValidator.IsValid(permDto.PermissionId))
                {
                    _logger.LogWarning("Skipping invalid permission format: {PermissionId}", permDto.PermissionId);
                    continue;
                }

                var (service, resource, action) = PermissionFormatValidator.Parse(permDto.PermissionId);

                if (service != request.ServiceName)
                {
                    _logger.LogWarning("Skipping permission {PermissionId} - service name mismatch (expected {Expected}, got {Actual})",
                        permDto.PermissionId, request.ServiceName, service);
                    continue;
                }

                if (existingPermissionsDict.TryGetValue(permDto.PermissionId, out var existingPermission))
                {
                    if (existingPermission.Description != permDto.Description)
                    {
                        existingPermission.Description = permDto.Description;
                        permissionsToUpdate.Add(existingPermission);
                    }
                    continue;
                }

                permissionsToCreate.Add(new Permission
                {
                    PermissionId = permDto.PermissionId,
                    ServiceName = service,
                    ResourceType = resource,
                    Action = action,
                    Description = permDto.Description,
                    RegisteredAt = DateTime.UtcNow
                });
            }

            if (permissionsToCreate.Any())
            {
                await _permissionRepository.CreateManyAsync(permissionsToCreate, cancellationToken);
                _logger.LogInformation("Registered {Count} permissions for {ServiceName}", permissionsToCreate.Count, request.ServiceName);

                try
                {
                    var events = permissionsToCreate.Select(p => new PermissionRegisteredEvent(
                        MessageId: Guid.NewGuid(),
                        MessageName: nameof(PermissionRegisteredEvent),
                        MessageType: MessageType.Event,
                        MessageVersion: "1.0.0",
                        PublishedBy: "iam",
                        ConsumedBy: [],
                        CorrelationId: Guid.NewGuid(),
                        CausationId: null,
                        OccurredAtUtc: DateTimeOffset.UtcNow,
                        IsPublic: false,
                        PermissionId: p.PermissionId,
                        ServiceName: p.ServiceName,
                        ResourceType: p.ResourceType,
                        Action: p.Action,
                        RegisteredAt: new DateTimeOffset(p.RegisteredAt, TimeSpan.Zero)
                    )).ToList();

                    await _publishEndpoint.PublishBatch(events, cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to publish registration events for {ServiceName}", request.ServiceName);
                }
            }

            if (permissionsToUpdate.Any())
            {
                await _permissionRepository.UpdateManyAsync(permissionsToUpdate, cancellationToken);
                _logger.LogInformation("Updated {Count} permissions for {ServiceName}", permissionsToUpdate.Count, request.ServiceName);
            }

            var allPermissions = existingPermissionsFromDb.Concat(permissionsToCreate);
            return allPermissions.Select(MapToResponse);
        }
        finally
        {
            _registrationSemaphore.Release();
        }
    }

    /// <inheritdoc />
    public async Task<IEnumerable<PermissionResponse>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        var permissions = await _permissionRepository.GetAllAsync(cancellationToken);
        return permissions.Select(MapToResponse);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<PermissionResponse>> GetByServiceAsync(string serviceName, CancellationToken cancellationToken = default)
    {
        var permissions = await _permissionRepository.GetByServiceAsync(serviceName, cancellationToken);
        return permissions.Select(MapToResponse);
    }

    /// <inheritdoc />
    public async Task<PermissionResponse?> GetByIdAsync(string permissionId, CancellationToken cancellationToken = default)
    {
        var permission = await _permissionRepository.GetByIdAsync(permissionId, cancellationToken);
        return permission != null ? MapToResponse(permission) : null;
    }

    /// <summary>
    /// Maps a permission entity to a permission response DTO.
    /// </summary>
    /// <param name="permission">The permission entity to map.</param>
    /// <returns>Permission response DTO.</returns>
    private static PermissionResponse MapToResponse(Permission permission) => new()
    {
        PermissionId = permission.PermissionId,
        ServiceName = permission.ServiceName,
        ResourceType = permission.ResourceType,
        Action = permission.Action,
        Description = permission.Description ?? string.Empty,
        CreatedAt = permission.RegisteredAt
    };
}
