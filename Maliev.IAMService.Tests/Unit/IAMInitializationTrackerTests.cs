using Maliev.IAMService.Api.Health;
using Xunit;

namespace Maliev.IAMService.Tests.Unit;

public class IAMInitializationTrackerTests
{
    [Fact]
    public void IsFullyInitialized_AllStepsComplete_ReturnsTrue()
    {
        var tracker = new IAMInitializationTracker();
        tracker.MarkDatabaseMigrationsComplete();
        tracker.MarkMassTransitStarted();
        tracker.MarkApiReady();

        Assert.True(tracker.IsFullyInitialized);
    }

    [Fact]
    public void IsFullyInitialized_DatabaseNotComplete_ReturnsFalse()
    {
        var tracker = new IAMInitializationTracker();
        tracker.MarkMassTransitStarted();
        tracker.MarkApiReady();

        Assert.False(tracker.IsFullyInitialized);
    }

    [Fact]
    public void IsFullyInitialized_MessagingNotStarted_ReturnsFalse()
    {
        var tracker = new IAMInitializationTracker();
        tracker.MarkDatabaseMigrationsComplete();
        tracker.MarkApiReady();

        Assert.False(tracker.IsFullyInitialized);
    }

    [Fact]
    public void IsFullyInitialized_ApiNotReady_ReturnsFalse()
    {
        var tracker = new IAMInitializationTracker();
        tracker.MarkDatabaseMigrationsComplete();
        tracker.MarkMassTransitStarted();

        Assert.False(tracker.IsFullyInitialized);
    }

    [Fact]
    public void GetProgress_NoStepsComplete_ReturnsWaitingForAll()
    {
        var tracker = new IAMInitializationTracker();
        var progress = tracker.GetProgress();

        Assert.Contains("database migrations", progress);
        Assert.Contains("messaging", progress);
        Assert.Contains("API", progress);
    }

    [Fact]
    public void GetProgress_SomeStepsComplete_ReturnsCorrectMessage()
    {
        var tracker = new IAMInitializationTracker();
        tracker.MarkDatabaseMigrationsComplete();
        var progress = tracker.GetProgress();

        Assert.Contains("messaging", progress);
        Assert.Contains("API", progress);
        Assert.DoesNotContain("database migrations", progress);
    }

    [Fact]
    public void GetProgress_AllComplete_ReturnsComplete()
    {
        var tracker = new IAMInitializationTracker();
        tracker.MarkDatabaseMigrationsComplete();
        tracker.MarkMassTransitStarted();
        tracker.MarkApiReady();

        var progress = tracker.GetProgress();

        Assert.Equal("Complete", progress);
    }
}
