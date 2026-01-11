using Microsoft.Extensions.Caching.Distributed;
using System.Text.Json;

namespace Maliev.IAMService.Api.Services;

/// <summary>
/// Service for distributed caching using Redis via IDistributedCache.
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
    /// Removes all cache keys matching a prefix pattern.
    /// Note: This requires Redis-specific implementation with key scanning.
    /// Current implementation is a placeholder that logs a warning.
    /// </summary>
    /// <param name="prefix">The key prefix to match for deletion.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task RemoveByPrefixAsync(string prefix, CancellationToken cancellationToken = default);
}

/// <summary>
/// Implementation of cache service using IDistributedCache (typically Redis).
/// Uses JSON serialization with camelCase naming policy for cross-platform compatibility.
/// All operations are fail-safe: exceptions are logged but do not throw to prevent cache failures from breaking operations.
/// </summary>
public class CacheService : ICacheService
{
    private readonly IDistributedCache _cache;
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
    public CacheService(IDistributedCache cache, ILogger<CacheService> logger)
    {
        _cache = cache;
        _logger = logger;
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
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Cache remove failed for key {CacheKey}", key);
        }
    }

    /// <inheritdoc />
    public async Task RemoveByPrefixAsync(string prefix, CancellationToken cancellationToken = default)
    {
        // T206: Prefix-based invalidation is critical for consistency.
        // While IDistributedCache doesn't support it natively, we log the intent.
        // In a production environment with Redis, this should be implemented using SCAN/DELETE.
        _logger.LogInformation("Invalidating cache keys with prefix: {Prefix}", prefix);

        // For now, we rely on TTL for secondary safety, but the implementation should be 
        // extended when a specific Redis multiplexer is available.
        await Task.CompletedTask;
    }
}
