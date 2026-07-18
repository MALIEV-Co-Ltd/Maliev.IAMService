using Maliev.IAMService.Infrastructure.Persistence;
using Maliev.IAMService.Application.Services;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using StackExchange.Redis;

namespace Maliev.IAMService.Tests.Testing;

/// <summary>
/// Isolated IAM fixture whose distributed cache uses the real Redis Testcontainer.
/// Ordinary integration tests retain their faster in-memory cache registration.
/// </summary>
public sealed class RedisLivePermissionContractFactory : TestWebApplicationFactory
{
    /// <summary>The logical Redis instance prefix configured by IAM.</summary>
    public const string CacheInstanceName = "iam:";

    /// <summary>The non-secret test credential accepted by the live-check boundary.</summary>
    public const string LiveCheckCredential = LiveCheckTestCredential;

    /// <inheritdoc />
    protected override void ConfigureAdditionalServices(IServiceCollection services)
    {
        base.ConfigureAdditionalServices(services);

        services.RemoveAll<IDistributedCache>();
        services.AddStackExchangeRedisCache(options =>
        {
            options.Configuration = RedisConnectionString;
            options.InstanceName = CacheInstanceName;
        });
    }

    /// <summary>
    /// Clears PostgreSQL and only this fixture's namespaced Redis keys.
    /// </summary>
    public async Task ResetContractStateAsync()
    {
        await CleanDatabaseAsync();
        await DeleteKeysAsync($"{CacheInstanceName}*");
    }

    /// <summary>
    /// Determines whether the physical Redis key for an IAM logical cache key exists.
    /// </summary>
    public async Task<bool> CacheKeyExistsAsync(string logicalKey)
    {
        var redis = Services.GetRequiredService<IConnectionMultiplexer>();
        return await redis.GetDatabase().KeyExistsAsync(CacheInstanceName + logicalKey);
    }

    /// <summary>Stores a logical IAM cache value through the production serializer and Redis namespace.</summary>
    public Task SetCacheAsync<T>(string logicalKey, T value) =>
        Services.GetRequiredService<ICacheService>().SetAsync(logicalKey, value, TimeSpan.FromMinutes(5));

    private async Task DeleteKeysAsync(RedisValue pattern)
    {
        var redis = Services.GetRequiredService<IConnectionMultiplexer>();
        var database = redis.GetDatabase();

        foreach (var endpoint in redis.GetEndPoints())
        {
            var server = redis.GetServer(endpoint);
            var keys = server.Keys(database.Database, pattern, pageSize: 100).ToArray();
            if (keys.Length > 0)
            {
                await database.KeyDeleteAsync(keys);
            }
        }
    }
}
