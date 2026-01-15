using MassTransit;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace Maliev.IAMService.Api.Consumers;

/// <summary>
/// Mock consumer for EmployeeCreated events to satisfy build requirements.
/// </summary>
public class EmployeeCreatedConsumer : IConsumer<object>
{
    private readonly ILogger<EmployeeCreatedConsumer> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="EmployeeCreatedConsumer"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    public EmployeeCreatedConsumer(ILogger<EmployeeCreatedConsumer> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Consumes the specified event.
    /// </summary>
    /// <param name="context">The consume context.</param>
    /// <returns>A task that represents the asynchronous consume operation.</returns>
    public Task Consume(ConsumeContext<object> context)
    {
        _logger.LogInformation("Received EmployeeCreated event. Auto-provisioning logic would go here.");
        return Task.CompletedTask;
    }
}
