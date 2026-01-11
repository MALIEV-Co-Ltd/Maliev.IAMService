using Maliev.IAMService.Data.Entities;
using Maliev.IAMService.Data.Repositories;
using Maliev.IAMService.Api.Models.Requests;
using Maliev.IAMService.Api.Models.Responses;
using Maliev.MessagingContracts.Generated;
using MassTransit;

namespace Maliev.IAMService.Api.Services;

/// <summary>
/// Service for managing role bindings (principal-role assignments) with cache invalidation and event publishing.
/// Supports global and resource-scoped bindings with optional expiration.
/// Publishes PrincipalRoleGrantedEvent and PrincipalRoleRevokedEvent via MassTransit.
/// Invalidates principal permission caches when bindings change.
/// </summary>
public interface IBindingService
{
    /// <summary>
    /// Grants a role to a principal with optional resource scope and expiration.
    /// Prevents duplicate bindings (same principal, role, and resource scope).
    /// Invalidates the principal's permission cache and publishes PrincipalRoleGrantedEvent.
    /// </summary>
    /// <param name="principalId">The principal ID to grant the role to.</param>
    /// <param name="request">Grant request with role ID, optional resource scope (type/ID), and optional expiration.</param>
    /// <param name="performedBy">The principal ID performing this action (for audit logging).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Created role binding response.</returns>
    Task<RoleBindingResponse> GrantRoleAsync(Guid principalId, GrantRoleRequest request, Guid performedBy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a role from a principal by deleting the binding.
    /// Invalidates the principal's permission cache and publishes PrincipalRoleRevokedEvent.
    /// </summary>
    /// <param name="principalId">The principal ID to revoke the role from.</param>
    /// <param name="bindingId">The binding ID to delete.</param>
    /// <param name="performedBy">The principal ID performing this action (for audit logging).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task RevokeRoleAsync(Guid principalId, Guid bindingId, Guid performedBy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves active role bindings for a principal.
    /// Filters out expired bindings automatically.
    /// </summary>
    /// <param name="principalId">The principal ID to get bindings for.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collection of role binding responses.</returns>
    Task<IEnumerable<RoleBindingResponse>> GetBindingsAsync(Guid principalId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Implementation of binding service with cache invalidation and event publishing.
/// Uses prefix-based cache invalidation to clear all permission caches for a principal.
/// Publishes events via MassTransit and writes audit logs for all binding changes.
/// </summary>
public class BindingService : IBindingService
{
    private readonly IBindingRepository _bindingRepository;
    private readonly IRoleRepository _roleRepository;
    private readonly IPrincipalRepository _principalRepository;
    private readonly ICacheService _cacheService;
    private readonly IAuditService _auditService;
    private readonly IPublishEndpoint _publishEndpoint;
    private readonly ILogger<BindingService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="BindingService"/> class.
    /// </summary>
    /// <param name="bindingRepository">The binding repository.</param>
    /// <param name="roleRepository">The role repository.</param>
    /// <param name="principalRepository">The principal repository.</param>
    /// <param name="cacheService">The cache service.</param>
    /// <param name="auditService">The audit service.</param>
    /// <param name="publishEndpoint">The publish endpoint.</param>
    /// <param name="logger">The logger.</param>
    public BindingService(
        IBindingRepository bindingRepository,
        IRoleRepository roleRepository,
        IPrincipalRepository principalRepository,
        ICacheService cacheService,
        IAuditService auditService,
        IPublishEndpoint publishEndpoint,
        ILogger<BindingService> logger)
    {
        _bindingRepository = bindingRepository;
        _roleRepository = roleRepository;
        _principalRepository = principalRepository;
        _cacheService = cacheService;
        _auditService = auditService;
        _publishEndpoint = publishEndpoint;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<RoleBindingResponse> GrantRoleAsync(Guid principalId, GrantRoleRequest request, Guid performedBy, CancellationToken cancellationToken = default)
    {
        // Verify principal exists
        var principal = await _principalRepository.GetByIdAsync(principalId, cancellationToken);
        if (principal == null)
            throw new InvalidOperationException($"Principal {principalId} not found");

        // Verify role exists
        var role = await _roleRepository.GetByIdAsync(request.RoleId, cancellationToken);
        if (role == null)
            throw new InvalidOperationException($"Role {request.RoleId} not found");

        // Check for duplicate binding (T065)
        var exists = await _bindingRepository.ExistsAsync(principalId, request.RoleId, request.ResourcePath, cancellationToken);
        if (exists)
            throw new InvalidOperationException($"Binding already exists for principal {principalId}, role {request.RoleId}, resource {request.ResourcePath}");

        var binding = new PrincipalRoleBinding
        {
            BindingId = Guid.NewGuid(),
            PrincipalId = principalId,
            RoleId = request.RoleId,
            ResourcePath = request.ResourcePath,
            GrantedAt = DateTime.UtcNow,
            ExpiresAt = request.ExpiresAt, // T066: Expiration handling
            GrantedBy = performedBy
        };

        var created = await _bindingRepository.CreateAsync(binding, cancellationToken);

        // T067: Invalidate cache for principal
        await _cacheService.RemoveByPrefixAsync($"iam:principal:{principalId}:", cancellationToken);

        // T070: Audit logging
        await _auditService.LogAsync("GRANT_ROLE", performedBy, new Dictionary<string, object>
        {
            ["principal_id"] = principalId,
            ["role_id"] = request.RoleId,
            ["binding_id"] = binding.BindingId,
            ["resource_path"] = request.ResourcePath ?? "global",
            ["expires_at"] = request.ExpiresAt?.ToString() ?? "never"
        }, cancellationToken);

        // T068: Publish event
        var principalRoleGrantedEvent = new PrincipalRoleGrantedEvent(
            MessageId: Guid.NewGuid(),
            MessageName: nameof(PrincipalRoleGrantedEvent),
            MessageType: MessageType.Event,
            MessageVersion: "1.0.0",
            PublishedBy: "iam",
            ConsumedBy: [],
            CorrelationId: Guid.NewGuid(),
            CausationId: null,
            OccurredAtUtc: DateTimeOffset.UtcNow,
            IsPublic: false,
            BindingId: created.BindingId,
            PrincipalId: created.PrincipalId,
            RoleId: created.RoleId,
            ResourceType: string.Empty, // Empty for backward compatibility
            ResourceId: created.ResourcePath ?? string.Empty, // Using ResourcePath as ResourceId for now
            GrantedAt: new DateTimeOffset(created.GrantedAt, TimeSpan.Zero),
            ExpiresAt: created.ExpiresAt.HasValue ? new DateTimeOffset(created.ExpiresAt.Value, TimeSpan.Zero) : DateTimeOffset.MaxValue
        );
        await _publishEndpoint.Publish(principalRoleGrantedEvent, cancellationToken);

        _logger.LogInformation("Granted role {RoleId} to principal {PrincipalId}", request.RoleId, principalId);

        return MapToResponse(created);
    }

    /// <inheritdoc />
    public async Task RevokeRoleAsync(Guid principalId, Guid bindingId, Guid performedBy, CancellationToken cancellationToken = default)
    {
        var binding = await _bindingRepository.GetByIdAsync(bindingId, cancellationToken);
        if (binding == null)
            throw new InvalidOperationException($"Binding {bindingId} not found");

        if (binding.PrincipalId != principalId)
            throw new InvalidOperationException($"Binding {bindingId} does not belong to principal {principalId}");

        await _bindingRepository.DeleteAsync(bindingId, cancellationToken);

        // T067: Invalidate cache for principal
        await _cacheService.RemoveByPrefixAsync($"iam:principal:{principalId}:", cancellationToken);

        // T070: Audit logging
        await _auditService.LogAsync("REVOKE_ROLE", performedBy, new Dictionary<string, object>
        {
            ["principal_id"] = principalId,
            ["role_id"] = binding.RoleId,
            ["binding_id"] = bindingId
        }, cancellationToken);

        // T069: Publish event
        var principalRoleRevokedEvent = new PrincipalRoleRevokedEvent(
            MessageId: Guid.NewGuid(),
            MessageName: nameof(PrincipalRoleRevokedEvent),
            MessageType: MessageType.Event,
            MessageVersion: "1.0.0",
            PublishedBy: "iam",
            ConsumedBy: [],
            CorrelationId: Guid.NewGuid(),
            CausationId: null,
            OccurredAtUtc: DateTimeOffset.UtcNow,
            IsPublic: false,
            BindingId: bindingId,
            PrincipalId: principalId,
            RoleId: binding.RoleId,
            RevokedAt: DateTimeOffset.UtcNow
        );
        await _publishEndpoint.Publish(principalRoleRevokedEvent, cancellationToken);

        _logger.LogInformation("Revoked role {RoleId} from principal {PrincipalId}", binding.RoleId, principalId);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<RoleBindingResponse>> GetBindingsAsync(Guid principalId, CancellationToken cancellationToken = default)
    {
        var bindings = await _bindingRepository.GetByPrincipalAsync(principalId, cancellationToken);
        return bindings.Select(MapToResponse);
    }

    /// <summary>
    /// Maps a principal role binding entity to a role binding response DTO.
    /// </summary>
    /// <param name="binding">The binding entity to map.</param>
    /// <returns>Role binding response DTO.</returns>
    private static RoleBindingResponse MapToResponse(PrincipalRoleBinding binding) => new()
    {
        BindingId = binding.BindingId,
        PrincipalId = binding.PrincipalId,
        RoleId = binding.RoleId,
        ResourcePath = binding.ResourcePath,
        GrantedAt = binding.GrantedAt,
        ExpiresAt = binding.ExpiresAt
    };
}
