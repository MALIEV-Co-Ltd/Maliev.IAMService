namespace Maliev.IAMService.Tests.Testing;

/// <summary>
/// Provides the isolated real-Redis IAM contract fixture.
/// </summary>
[CollectionDefinition(Name)]
public sealed class RedisLivePermissionContractCollection
    : ICollectionFixture<RedisLivePermissionContractFactory>
{
    /// <summary>The xUnit collection name used by the contract tests.</summary>
    public const string Name = "Redis Live Permission Contract";
}
