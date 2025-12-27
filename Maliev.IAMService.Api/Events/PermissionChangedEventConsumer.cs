using MassTransit;
using Maliev.IAMService.Api.Services;
using Maliev.MessagingContracts.Generated;

namespace Maliev.IAMService.Api.Events;

// T095: Consumer for iam.principal-role-granted events
public class PrincipalRoleGrantedEventConsumer : IConsumer<PrincipalRoleGrantedEvent>
{
    private readonly ICacheService _cacheService;
    private readonly ILogger<PrincipalRoleGrantedEventConsumer> _logger;

    public PrincipalRoleGrantedEventConsumer(ICacheService cacheService, ILogger<PrincipalRoleGrantedEventConsumer> logger)
    {
        _cacheService = cacheService;
        _logger = logger;
    }

    public async Task Consume(ConsumeContext<PrincipalRoleGrantedEvent> context)
    {
        var evt = context.Message;

        // Invalidate all cache entries for this principal
        await _cacheService.RemoveByPrefixAsync($"iam:principal:{evt.PrincipalId}:", CancellationToken.None);

        _logger.LogInformation("Invalidated permission cache for principal {PrincipalId} after role {RoleId} granted",
            evt.PrincipalId, evt.RoleId);
    }
}

// T096: Consumer for iam.principal-role-revoked events
public class PrincipalRoleRevokedEventConsumer : IConsumer<PrincipalRoleRevokedEvent>
{
    private readonly ICacheService _cacheService;
    private readonly ILogger<PrincipalRoleRevokedEventConsumer> _logger;

    public PrincipalRoleRevokedEventConsumer(ICacheService cacheService, ILogger<PrincipalRoleRevokedEventConsumer> logger)
    {
        _cacheService = cacheService;
        _logger = logger;
    }

    public async Task Consume(ConsumeContext<PrincipalRoleRevokedEvent> context)
    {
        var evt = context.Message;

        // Invalidate all cache entries for this principal
        await _cacheService.RemoveByPrefixAsync($"iam:principal:{evt.PrincipalId}:", CancellationToken.None);

        _logger.LogInformation("Invalidated permission cache for principal {PrincipalId} after role {RoleId} revoked",
            evt.PrincipalId, evt.RoleId);
    }
}
