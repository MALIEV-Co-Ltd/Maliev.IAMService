using Maliev.IAMService.Application.Services;
using Maliev.MessagingContracts.Contracts.Iam;
using MassTransit;

namespace Maliev.IAMService.Api.Events;

// T097: Consumer for iam.role-updated events
/// <summary>
/// Consumer for RoleUpdatedEvent. Invalidates cache for all principals when a role is updated.
/// </summary>
public class RoleUpdatedEventConsumer : IConsumer<RoleUpdatedEvent>
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<RoleUpdatedEventConsumer> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="RoleUpdatedEventConsumer"/> class.
    /// </summary>
    /// <param name="scopeFactory">The service scope factory.</param>
    /// <param name="logger">The logger.</param>
    public RoleUpdatedEventConsumer(IServiceScopeFactory scopeFactory, ILogger<RoleUpdatedEventConsumer> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task Consume(ConsumeContext<RoleUpdatedEvent> context)
    {
        var evt = context.Message;

        using var scope = _scopeFactory.CreateScope();
        var cacheService = scope.ServiceProvider.GetRequiredService<ICacheService>();

        // When a role is updated, we need to invalidate cache for ALL principals
        // This is a broad invalidation but ensures consistency
        // In production, you might track which principals have this role and invalidate selectively
        await cacheService.RemoveByPrefixAsync("iam:principal:", context.CancellationToken);

        _logger.LogWarning("Invalidated ALL principal permission caches after role {RoleId} was updated", evt.RoleId);
    }
}
