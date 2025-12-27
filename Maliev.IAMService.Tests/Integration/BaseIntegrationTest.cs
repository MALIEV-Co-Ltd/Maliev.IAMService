using Maliev.IAMService.Tests.Testing;
using Xunit;

namespace Maliev.IAMService.Tests.Integration;

/// <summary>
/// Base class for all integration tests.
/// Creates a fresh TestWebApplicationFactory for each test class to avoid state accumulation issues.
/// Call CleanDatabaseAsync() at the start of each test method for test isolation.
/// </summary>
public abstract class BaseIntegrationTest : IAsyncLifetime
{
    protected HttpClient Client = null!;
    protected TestWebApplicationFactory Factory = null!;

    /// <summary>
    /// Called before first test in the class. Creates a new factory instance.
    /// </summary>
    public virtual async Task InitializeAsync()
    {
        Factory = new TestWebApplicationFactory();
        await Factory.InitializeAsync();

        // Use authenticated client with all IAM permissions for testing
        Client = Factory.CreateAuthenticatedClientWithAllPermissions();
    }

    /// <summary>
    /// Called after all tests in the class complete. Disposes the factory and client.
    /// </summary>
    public virtual async Task DisposeAsync()
    {
        Client?.Dispose();
        if (Factory != null)
        {
            await Factory.DisposeAsync();
        }
    }

    /// <summary>
    /// Cleans the database to ensure test isolation.
    /// Call this at the start of each test method to ensure a clean state.
    /// </summary>
    protected async Task CleanDatabaseAsync()
    {
        await Factory.CleanDatabaseAsync();
    }
}
