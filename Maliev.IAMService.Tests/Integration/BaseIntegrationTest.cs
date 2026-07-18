using Maliev.IAMService.Tests.Testing;
using Xunit;

namespace Maliev.IAMService.Tests.Integration;

/// <summary>
/// Base class for all integration tests.
/// Uses a shared TestWebApplicationFactory via XUnit collection fixture to avoid container overhead.
/// Call CleanDatabaseAsync() at the start of each test method for test isolation.
/// </summary>
[Collection("Integration Tests")]
public abstract class BaseIntegrationTest
{
    protected readonly HttpClient Client;
    protected readonly TestWebApplicationFactory Factory;

    protected BaseIntegrationTest(TestWebApplicationFactory factory)
    {
        Factory = factory;
        // Use authenticated client with all IAM permissions for testing
        Client = Factory.CreateAuthenticatedClientWithAllPermissions();
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
