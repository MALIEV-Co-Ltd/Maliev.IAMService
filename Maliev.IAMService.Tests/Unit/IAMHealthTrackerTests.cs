using Maliev.IAMService.Api.Health;
using Xunit;

namespace Maliev.IAMService.Tests.Unit;

/// <summary>
/// Unit tests for IAMInitializationTracker and IAMReadinessHealthCheck.
/// These types cannot be exercised via integration tests because IAMInitializationHostedService
/// is disabled in test configuration.
/// </summary>
public class IAMHealthTrackerTests
{
    [Fact]
    public void IAMInitializationTracker_InitialState_NotFullyInitialized()
    {
        var tracker = new IAMInitializationTracker();

        Assert.False(tracker.IsFullyInitialized);
    }

    [Fact]
    public void IAMInitializationTracker_AfterAllMarked_IsFullyInitialized()
    {
        var tracker = new IAMInitializationTracker();

        tracker.MarkDatabaseMigrationsComplete();
        tracker.MarkMassTransitStarted();
        tracker.MarkApiReady();

        Assert.True(tracker.IsFullyInitialized);
    }

    [Fact]
    public void IAMInitializationTracker_GetProgress_WhenNoneComplete_ListsAllSteps()
    {
        var tracker = new IAMInitializationTracker();

        var progress = tracker.GetProgress();

        Assert.Contains("database migrations", progress);
        Assert.Contains("messaging", progress);
        Assert.Contains("API", progress);
    }

    [Fact]
    public void IAMInitializationTracker_GetProgress_WhenFullyInitialized_ReturnsComplete()
    {
        var tracker = new IAMInitializationTracker();
        tracker.MarkDatabaseMigrationsComplete();
        tracker.MarkMassTransitStarted();
        tracker.MarkApiReady();

        var progress = tracker.GetProgress();

        Assert.Equal("Complete", progress);
    }

    [Fact]
    public void IAMInitializationTracker_GetProgress_WhenOnlySomeDone_ListsMissing()
    {
        var tracker = new IAMInitializationTracker();
        tracker.MarkDatabaseMigrationsComplete();
        // MassTransit and API not marked

        var progress = tracker.GetProgress();

        Assert.Contains("messaging", progress);
        Assert.Contains("API", progress);
        Assert.DoesNotContain("database migrations", progress);
    }

    [Fact]
    public async Task IAMReadinessHealthCheck_WhenNotInitialized_ReturnsUnhealthy()
    {
        var tracker = new IAMInitializationTracker(); // Not fully initialized
        var healthCheck = new IAMReadinessHealthCheck(tracker);

        var context = new Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckContext
        {
            Registration = new Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckRegistration(
                "iam_ready", healthCheck, null, null)
        };

        var result = await healthCheck.CheckHealthAsync(context, CancellationToken.None);

        Assert.Equal(Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Unhealthy, result.Status);
    }

    [Fact]
    public async Task IAMReadinessHealthCheck_WhenFullyInitialized_ReturnsHealthy()
    {
        var tracker = new IAMInitializationTracker();
        tracker.MarkDatabaseMigrationsComplete();
        tracker.MarkMassTransitStarted();
        tracker.MarkApiReady();

        var healthCheck = new IAMReadinessHealthCheck(tracker);

        var context = new Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckContext
        {
            Registration = new Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckRegistration(
                "iam_ready", healthCheck, null, null)
        };

        var result = await healthCheck.CheckHealthAsync(context, CancellationToken.None);

        Assert.Equal(Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Healthy, result.Status);
    }
}
