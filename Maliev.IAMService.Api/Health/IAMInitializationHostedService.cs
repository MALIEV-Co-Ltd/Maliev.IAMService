using Microsoft.Extensions.Hosting;

namespace Maliev.IAMService.Api.Health;

/// <summary>
/// Hosted service that marks IAM as fully initialized after the application has started.
/// This ensures MassTransit consumers are listening before we report as ready.
/// </summary>
public class IAMInitializationHostedService : IHostedService
{
    private readonly IAMInitializationTracker _tracker;
    private readonly IHostApplicationLifetime _applicationLifetime;
    private readonly ILogger<IAMInitializationHostedService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="IAMInitializationHostedService"/> class.
    /// </summary>
    /// <param name="tracker">The initialization tracker.</param>
    /// <param name="applicationLifetime">The application lifetime.</param>
    /// <param name="logger">The logger.</param>
    public IAMInitializationHostedService(
        IAMInitializationTracker tracker,
        IHostApplicationLifetime applicationLifetime,
        ILogger<IAMInitializationHostedService> logger)
    {
        _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
        _applicationLifetime = applicationLifetime ?? throw new ArgumentNullException(nameof(applicationLifetime));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Starts the hosted service and waits for application to be fully started.
    /// </summary>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _applicationLifetime.ApplicationStarted.Register(() =>
        {
            _logger.LogInformation("Application fully started, marking IAM service as initialized");
            _tracker.MarkMassTransitStarted();
            _tracker.MarkApiReady();
        });

        return Task.CompletedTask;
    }

    /// <summary>
    /// Stops the hosted service.
    /// </summary>
    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
