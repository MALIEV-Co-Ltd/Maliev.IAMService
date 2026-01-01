using MassTransit;
using Maliev.IAMService.Api.Services;
using Maliev.MessagingContracts.Generated;

namespace Maliev.IAMService.Api.Events;

// T097: Consumer for iam.role-updated events
/// <summary>
/// Consumer for RoleUpdatedEvent. Invalidates cache for all principals when a role is updated.
/// </summary>
public class RoleUpdatedEventConsumer : IConsumer<RoleUpdatedEvent>
{
    private readonly ICacheService _cacheService;
    private readonly ILogger<RoleUpdatedEventConsumer> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="RoleUpdatedEventConsumer"/> class.
    /// </summary>
    /// <param name="cacheService">The cache service.</param>
    /// <param name="logger">The logger.</param>
    public RoleUpdatedEventConsumer(ICacheService cacheService, ILogger<RoleUpdatedEventConsumer> logger)
    {
        _cacheService = cacheService;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task Consume(ConsumeContext<RoleUpdatedEvent> context)
    {
        var evt = context.Message;

        // When a role is updated, we need to invalidate cache for ALL principals
        // This is a broad invalidation but ensures consistency
        // In production, you might track which principals have this role and invalidate selectively
        await _cacheService.RemoveByPrefixAsync("iam:principal:", CancellationToken.None);

        _logger.LogWarning("Invalidated ALL principal permission caches after role {RoleId} was updated", evt.RoleId);
    }
}
