using Xunit;

namespace Maliev.IAMService.Tests.Testing;

/// <summary>
/// Defines a test collection to ensure integration tests run sequentially
/// and share the same test fixture instance to avoid container/resource conflicts.
/// </summary>
[CollectionDefinition("Integration Tests")]
public class IntegrationTestCollection : ICollectionFixture<TestWebApplicationFactory>
{
    // This class has no code, and is never instantiated.
    // Its purpose is simply to be the place to apply [CollectionDefinition] and all the
    // ICollectionFixture<> interfaces.
}
