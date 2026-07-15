using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;
using System.Text.Json;

namespace Maliev.IAMService.Application.Services;

/// <summary>
/// Service for distributed caching using Redis via IDistributedCache and IConnectionMultiplexer.
/// Provides JSON serialization/deserialization with camelCase naming policy.
/// Default TTL is 15 minutes if not specified. Failures are logged but do not throw exceptions.
/// </summary>
public interface ICacheService
{
    /// <summary>
    /// Retrieves a value from cache by key with JSON deserialization.
    /// Returns default(T) if key doesn't exist or deserialization fails.
    /// Failures are logged but do not throw exceptions.
    /// </summary>
    /// <typeparam name="T">The type to deserialize the cached value to.</typeparam>
    /// <param name="key">The cache key to retrieve.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Cached value if found and deserialized successfully; otherwise default(T).</returns>
    Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Stores a value in cache with JSON serialization.
    /// Uses camelCase property naming and configurable expiration (default 15 minutes).
    /// Failures are logged but do not throw exceptions.
    /// </summary>
    /// <typeparam name="T">The type of value to cache.</typeparam>
    /// <param name="key">The cache key to store under.</param>
    /// <param name="value">The value to cache.</param>
    /// <param name="expiration">Optional expiration duration (default 15 minutes if not specified).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task SetAsync<T>(string key, T value, TimeSpan? expiration = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes a specific key from cache.
    /// Failures are logged but do not throw exceptions.
    /// </summary>
    /// <param name="key">The cache key to remove.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task RemoveAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes all cache keys matching a prefix pattern across all Redis nodes.
    /// Uses SCAN-based iteration to efficiently find and delete keys without blocking.
    /// </summary>
    /// <param name="prefix">The key prefix to match for deletion.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task RemoveByPrefixAsync(string prefix, CancellationToken cancellationToken = default);
}

/// <summary>
/// Implementation of cache service using IDistributedCache and IConnectionMultiplexer.
/// Uses JSON serialization with camelCase naming policy for cross-platform compatibility.
/// All operations are fail-safe: exceptions are logged but do not throw to prevent cache failures from breaking operations.
/// </summary>
public class CacheService : ICacheService
{
    private readonly IDistributedCache _cache;
    private readonly IConnectionMultiplexer? _redis;
    private readonly ILogger<CacheService> _logger;
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    /// <summary>
    /// Initializes a new instance of the <see cref="CacheService"/> class.
    /// </summary>
    /// <param name="cache">The distributed cache.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="redis">The Redis connection multiplexer, when Redis is enabled.</param>
    public CacheService(
        IDistributedCache cache,
        ILogger<CacheService> logger,
        IConnectionMultiplexer? redis = null)
    {
        _cache = cache;
        _logger = logger;
        _redis = redis;
    }

    /// <inheritdoc />
    public async Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default)
    {
        try
        {
            var data = await _cache.GetStringAsync(key, cancellationToken);
            if (string.IsNullOrEmpty(data))
                return default;

            return JsonSerializer.Deserialize<T>(data, _jsonOptions);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Cache get failed for key {CacheKey}", key);
            return default;
        }
    }

    /// <inheritdoc />
    public async Task SetAsync<T>(string key, T value, TimeSpan? expiration = null, CancellationToken cancellationToken = default)
    {
        try
        {
            var data = JsonSerializer.Serialize(value, _jsonOptions);
            var options = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = expiration ?? TimeSpan.FromMinutes(15)
            };

            await _cache.SetStringAsync(key, data, options, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Cache set failed for key {CacheKey}", key);
        }
    }

    /// <inheritdoc />
    public async Task RemoveAsync(string key, CancellationToken cancellationToken = default)
    {
        try
        {
            await _cache.RemoveAsync(key, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Cache remove failed for key {CacheKey}", key);
        }
    }

    /// <inheritdoc />
    public async Task RemoveByPrefixAsync(string prefix, CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_redis == null)
            {
                _logger.LogDebug("Redis is not configured. Skipping prefix-based invalidation for: {Prefix}", prefix);
                return;
            }

            if (!_redis.IsConnected)
            {
                _logger.LogWarning("Redis is not connected. Skipping prefix-based invalidation for: {Prefix}", prefix);
                return;
            }

            var endpoints = _redis.GetEndPoints();
            var db = _redis.GetDatabase();
            var tasks = new List<Task>();

            var redisPattern = "iam:" + prefix + "*";

            foreach (var endpoint in endpoints)
            {
                var server = _redis.GetServer(endpoint);
                var keys = server.Keys(pattern: redisPattern).ToArray();
                if (keys.Length > 0)
                {
                    tasks.Add(db.KeyDeleteAsync(keys));
                }
            }

            if (tasks.Count > 0)
            {
                await Task.WhenAll(tasks);
                _logger.LogInformation("Successfully invalidated {Count} cache keys with prefix pattern: {Prefix}", tasks.Count, redisPattern);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to remove cache keys by prefix {Prefix}", prefix);
        }
    }
}
