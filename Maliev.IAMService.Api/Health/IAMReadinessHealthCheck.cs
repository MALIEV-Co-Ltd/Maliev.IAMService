using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Maliev.IAMService.Api.Health;

/// <summary>
/// Health check that only reports healthy when IAM service is fully initialized
/// and ready to accept permission/role registration requests.
/// </summary>
public class IAMReadinessHealthCheck : IHealthCheck
{
    private readonly IAMInitializationTracker _tracker;

    /// <summary>
    /// Initializes a new instance of the <see cref="IAMReadinessHealthCheck"/> class.
    /// </summary>
    /// <param name="tracker">The initialization tracker.</param>
    public IAMReadinessHealthCheck(IAMInitializationTracker tracker)
    {
        _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
    }

    /// <inheritdoc />
    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        if (_tracker.IsFullyInitialized)
        {
            return Task.FromResult(HealthCheckResult.Healthy("IAM service is fully initialized and ready to accept registrations"));
        }

        // Report as Degraded (not Unhealthy) during initialization to allow service to start
        // This prevents Aspire from marking the service as failed during normal startup
        var message = $"IAM service is initializing. Progress: {_tracker.GetProgress()}";
        return Task.FromResult(HealthCheckResult.Degraded(message));
    }
}

/// <summary>
/// Tracks the initialization state of the IAM service.
/// </summary>
public class IAMInitializationTracker
{
    private bool _databaseMigrationsComplete;
    private bool _massTransitStarted;
    private bool _apiReady;

    /// <summary>
    /// Gets a value indicating whether the service is fully initialized.
    /// </summary>
    public bool IsFullyInitialized => _databaseMigrationsComplete && _massTransitStarted && _apiReady;

    /// <summary>
    /// Marks database migrations as complete.
    /// </summary>
    public void MarkDatabaseMigrationsComplete() => _databaseMigrationsComplete = true;
    /// <summary>
    /// Marks MassTransit as started.
    /// </summary>
    public void MarkMassTransitStarted() => _massTransitStarted = true;
    /// <summary>
    /// Marks the API as ready.
    /// </summary>
    public void MarkApiReady() => _apiReady = true;

    /// <summary>
    /// Gets a string description of the initialization progress.
    /// </summary>
    /// <returns>Progress description.</returns>
    public string GetProgress()
    {
        var steps = new List<string>();
        if (!_databaseMigrationsComplete) steps.Add("database migrations");
        if (!_massTransitStarted) steps.Add("messaging");
        if (!_apiReady) steps.Add("API");

        return steps.Count == 0 ? "Complete" : $"Waiting for: {string.Join(", ", steps)}";
    }
}
