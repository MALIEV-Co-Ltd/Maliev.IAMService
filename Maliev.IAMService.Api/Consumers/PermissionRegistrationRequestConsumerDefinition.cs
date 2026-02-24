using Maliev.IAMService.Api.Consumers;
using MassTransit;

namespace Maliev.IAMService.Api.Consumers;

/// <summary>
/// Definition for the PermissionRegistrationRequestConsumer.
/// Limits concurrency to 1 to prevent race conditions during parallel service startup.
/// </summary>
public class PermissionRegistrationRequestConsumerDefinition : ConsumerDefinition<PermissionRegistrationRequestConsumer>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PermissionRegistrationRequestConsumerDefinition"/> class.
    /// </summary>
    public PermissionRegistrationRequestConsumerDefinition()
    {
        // Limit to 1 concurrent message across all instances (since this is startup-only and race-sensitive)
        ConcurrentMessageLimit = 1;
    }

    /// <summary>
    /// Configures the consumer endpoint.
    /// </summary>
    /// <param name="endpointConfigurator">The endpoint configurator.</param>
    /// <param name="consumerConfigurator">The consumer configurator.</param>
    /// <param name="context">The registration context.</param>
    protected override void ConfigureConsumer(IReceiveEndpointConfigurator endpointConfigurator, IConsumerConfigurator<PermissionRegistrationRequestConsumer> consumerConfigurator, IRegistrationContext context)
    {
        // Add retry policy with small delay to handle transient DB issues
        endpointConfigurator.UseMessageRetry(r => r.Interval(3, TimeSpan.FromMilliseconds(200)));
    }
}
