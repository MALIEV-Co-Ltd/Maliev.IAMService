using Maliev.IAMService.Api.Services;
using Maliev.MessagingContracts.Contracts.Iam;
using MassTransit;

namespace Maliev.IAMService.Api.Events;

// T095: Consumer for iam.principal-role-granted events
/// <summary>
/// Consumer for PrincipalRoleGrantedEvent. Invalidates permission cache when a role is granted.
/// </summary>
public class PrincipalRoleGrantedEventConsumer : IConsumer<PrincipalRoleGrantedEvent>
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<PrincipalRoleGrantedEventConsumer> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="PrincipalRoleGrantedEventConsumer"/> class.
    /// </summary>
    /// <param name="scopeFactory">The service scope factory.</param>
    /// <param name="logger">The logger.</param>
    public PrincipalRoleGrantedEventConsumer(IServiceScopeFactory scopeFactory, ILogger<PrincipalRoleGrantedEventConsumer> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task Consume(ConsumeContext<PrincipalRoleGrantedEvent> context)
    {
        var evt = context.Message;

        using var scope = _scopeFactory.CreateScope();
        var cacheService = scope.ServiceProvider.GetRequiredService<ICacheService>();

        // Invalidate all cache entries for this principal
        await cacheService.RemoveByPrefixAsync($"iam:principal:{evt.PrincipalId}:", context.CancellationToken);

        _logger.LogInformation("Invalidated permission cache for principal {PrincipalId} after role {RoleId} granted",
            evt.PrincipalId, evt.RoleId);
    }
}

// T096: Consumer for iam.principal-role-revoked events
/// <summary>
/// Consumer for PrincipalRoleRevokedEvent. Invalidates permission cache when a role is revoked.
/// </summary>
public class PrincipalRoleRevokedEventConsumer : IConsumer<PrincipalRoleRevokedEvent>
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<PrincipalRoleRevokedEventConsumer> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="PrincipalRoleRevokedEventConsumer"/> class.
    /// </summary>
    /// <param name="scopeFactory">The service scope factory.</param>
    /// <param name="logger">The logger.</param>
    public PrincipalRoleRevokedEventConsumer(IServiceScopeFactory scopeFactory, ILogger<PrincipalRoleRevokedEventConsumer> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task Consume(ConsumeContext<PrincipalRoleRevokedEvent> context)
    {
        var evt = context.Message;

        using var scope = _scopeFactory.CreateScope();
        var cacheService = scope.ServiceProvider.GetRequiredService<ICacheService>();

        // Invalidate all cache entries for this principal
        await cacheService.RemoveByPrefixAsync($"iam:principal:{evt.PrincipalId}:", context.CancellationToken);

        _logger.LogInformation("Invalidated permission cache for principal {PrincipalId} after role {RoleId} revoked",
            evt.PrincipalId, evt.RoleId);
    }
}
