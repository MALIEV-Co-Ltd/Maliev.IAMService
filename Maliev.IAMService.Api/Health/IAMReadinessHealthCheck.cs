using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Maliev.IAMService.Api.Health;

/// <summary>
/// Health check that only reports healthy when IAM service is fully initialized
/// and ready to accept permission/role registration requests.
/// </summary>
public class IAMReadinessHealthCheck : IHealthCheck
{
    private readonly IAMInitializationTracker _tracker;

    public IAMReadinessHealthCheck(IAMInitializationTracker tracker)
    {
        _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
    }

    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        if (_tracker.IsFullyInitialized)
        {
            return Task.FromResult(HealthCheckResult.Healthy("IAM service is fully initialized and ready to accept registrations"));
        }

        var message = $"IAM service is still initializing. Progress: {_tracker.GetProgress()}";
        return Task.FromResult(HealthCheckResult.Unhealthy(message));
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

    public bool IsFullyInitialized => _databaseMigrationsComplete && _massTransitStarted && _apiReady;

    public void MarkDatabaseMigrationsComplete() => _databaseMigrationsComplete = true;
    public void MarkMassTransitStarted() => _massTransitStarted = true;
    public void MarkApiReady() => _apiReady = true;

    public string GetProgress()
    {
        var steps = new List<string>();
        if (!_databaseMigrationsComplete) steps.Add("database migrations");
        if (!_massTransitStarted) steps.Add("messaging");
        if (!_apiReady) steps.Add("API");

        return steps.Count == 0 ? "Complete" : $"Waiting for: {string.Join(", ", steps)}";
    }
}
