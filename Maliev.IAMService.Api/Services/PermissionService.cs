using Maliev.IAMService.Data.Entities;
using Maliev.IAMService.Data.Repositories;
using Maliev.IAMService.Api.Validators;
using Maliev.IAMService.Api.Models.Requests;
using Maliev.IAMService.Api.Models.Responses;
using Maliev.MessagingContracts.Generated;
using MassTransit;

namespace Maliev.IAMService.Api.Services;

/// <summary>
/// Service for managing permissions and their registration from external services.
/// Validates permission format (service.resource.action) and publishes events via MassTransit.
/// Ensures permissions are unique and properly scoped to their owning service.
/// </summary>
public interface IPermissionService
{
    /// <summary>
    /// Registers permissions from an external service with format validation.
    /// Permission IDs must follow the format: {service}.{resource}.{action} (e.g., "user-service.profile.update").
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

    /// <summary>
    /// Initializes a new instance of the <see cref="PermissionService"/> class.
    /// </summary>
    /// <param name="permissionRepository">The permission repository.</param>
    /// <param name="publishEndpoint">The publish endpoint.</param>
    /// <param name="logger">The logger.</param>
    public PermissionService(IPermissionRepository permissionRepository, IPublishEndpoint publishEndpoint, ILogger<PermissionService> logger)
    {
        _permissionRepository = permissionRepository;
        _publishEndpoint = publishEndpoint;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<IEnumerable<PermissionResponse>> RegisterPermissionsAsync(RegisterPermissionsRequest request, CancellationToken cancellationToken = default)
    {
        // Validate service name
        if (string.IsNullOrWhiteSpace(request.ServiceName))
            throw new ArgumentException("Service name is required", nameof(request.ServiceName));

        // Fetch existing permissions for this service once to avoid N+1 queries
        var existingPermissions = (await _permissionRepository.GetByServiceAsync(request.ServiceName, cancellationToken))
            .Select(p => p.PermissionId)
            .ToHashSet();

        // Validate and parse permissions
        var permissionsToCreate = new List<Permission>();
        foreach (var permDto in request.Permissions)
        {
            // Validate permission format
            if (!PermissionFormatValidator.IsValid(permDto.PermissionId))
                throw new ArgumentException($"Invalid permission format: {permDto.PermissionId}. Expected format: {{service}}.{{resource}}.{{action}}");

            var (service, resource, action) = PermissionFormatValidator.Parse(permDto.PermissionId);

            // Ensure service name matches
            if (service != request.ServiceName)
                throw new ArgumentException($"Permission {permDto.PermissionId} does not match service name {request.ServiceName}");

            // Check for duplicate permission IDs in the request
            if (permissionsToCreate.Any(p => p.PermissionId == permDto.PermissionId))
                throw new InvalidOperationException($"Duplicate permission ID in request: {permDto.PermissionId}");

            // Check if permission already exists using local cache
            if (existingPermissions.Contains(permDto.PermissionId))
            {
                _logger.LogDebug("Permission {PermissionId} already exists, skipping", permDto.PermissionId);
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
            _logger.LogInformation("Registered {Count} permissions for service {ServiceName}", permissionsToCreate.Count, request.ServiceName);

            // Publish permission registered events
            foreach (var permission in permissionsToCreate)
            {
                var permissionRegisteredEvent = new PermissionRegisteredEvent(
                    PermissionId: permission.PermissionId,
                    ServiceName: permission.ServiceName,
                    ResourceType: permission.ResourceType,
                    Action: permission.Action,
                    RegisteredAt: new DateTimeOffset(permission.RegisteredAt, TimeSpan.Zero)
                );
                await _publishEndpoint.Publish(permissionRegisteredEvent, CancellationToken.None);
            }
        }

        // Return all permissions for the service
        return await GetByServiceAsync(request.ServiceName, cancellationToken);
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
