using Maliev.IAMService.Api.Health;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Xunit;

namespace Maliev.IAMService.Tests.Unit;

public class IAMReadinessHealthCheckTests
{
    [Fact]
    public async Task CheckHealthAsync_WhenInitialized_ReturnsHealthy()
    {
        var tracker = new IAMInitializationTracker();
        tracker.MarkDatabaseMigrationsComplete();
        tracker.MarkMassTransitStarted();
        tracker.MarkApiReady();

        var healthCheck = new IAMReadinessHealthCheck(tracker);
        var result = await healthCheck.CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Healthy, result.Status);
    }

    [Fact]
    public async Task CheckHealthAsync_WhenNotInitialized_ReturnsUnhealthy()
    {
        var tracker = new IAMInitializationTracker();

        var healthCheck = new IAMReadinessHealthCheck(tracker);
        var result = await healthCheck.CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
    }

    [Fact]
    public async Task CheckHealthAsync_WhenPartiallyInitialized_ReturnsUnhealthyWithProgress()
    {
        var tracker = new IAMInitializationTracker();
        tracker.MarkDatabaseMigrationsComplete();

        var healthCheck = new IAMReadinessHealthCheck(tracker);
        var result = await healthCheck.CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Contains("messaging", result.Description);
    }

    [Fact]
    public void Constructor_WithNullTracker_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new IAMReadinessHealthCheck(null!));
    }
}
