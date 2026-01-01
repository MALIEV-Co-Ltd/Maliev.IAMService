using Maliev.IAMService.Data.Repositories;
using Maliev.IAMService.Api.Models.Requests;
using Maliev.IAMService.Api.Models.Responses;
using System.Diagnostics;

namespace Maliev.IAMService.Api.Services;

/// <summary>
/// Service for resolving and checking permissions for principals with Redis caching.
/// Provides &lt;10ms permission checks through aggressive caching with 5-minute TTL.
/// Supports both global and resource-scoped permission resolution with hierarchical matching.
/// </summary>
public interface IPermissionResolver
{
    /// <summary>
    /// Resolves all effective permissions for a principal by aggregating permissions from all assigned roles.
    /// Results are cached in Redis with a 5-minute TTL for optimal performance.
    /// Supports global roles and resource-scoped roles with hierarchical path matching.
    /// </summary>
    /// <param name="request">Permission resolution request containing principal ID and optional resource scope (type and ID).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Response containing the list of unique permission IDs granted to the principal and cache status.</returns>
    Task<ResolvePermissionsResponse> ResolvePermissionsAsync(ResolvePermissionsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a principal has a specific permission with latency tracking.
    /// Internally uses ResolvePermissionsAsync and benefits from the same caching strategy.
    /// Target latency: &lt;10ms for cached results, &lt;50ms for cache misses.
    /// </summary>
    /// <param name="request">Permission check request containing principal ID, permission ID, and optional resource scope.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Response indicating whether the permission is allowed, cache status, and latency in milliseconds.</returns>
    Task<CheckPermissionResponse> CheckPermissionAsync(CheckPermissionRequest request, CancellationToken cancellationToken = default);
}

/// <summary>
/// Implementation of permission resolver with Redis caching for high-performance permission checks.
/// Uses a 5-minute cache TTL and supports hierarchical resource path matching (e.g., projects/123/* matches projects/123/documents/456).
/// </summary>
public class PermissionResolver : IPermissionResolver
{
    private readonly IBindingRepository _bindingRepository;
    private readonly ICacheService _cacheService;
    private readonly ILogger<PermissionResolver> _logger;
    private const int CacheTtlMinutes = 5;

    /// <summary>
    /// Initializes a new instance of the <see cref="PermissionResolver"/> class.
    /// </summary>
    /// <param name="bindingRepository">The binding repository.</param>
    /// <param name="cacheService">The cache service.</param>
    /// <param name="logger">The logger.</param>
    public PermissionResolver(
        IBindingRepository bindingRepository,
        ICacheService cacheService,
        ILogger<PermissionResolver> logger)
    {
        _bindingRepository = bindingRepository;
        _cacheService = cacheService;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<ResolvePermissionsResponse> ResolvePermissionsAsync(ResolvePermissionsRequest request, CancellationToken cancellationToken = default)
    {
        var cacheKey = GetCacheKey(request.PrincipalId, request.ResourcePath);

        // T086: Try to get from cache
        var cached = await _cacheService.GetAsync<ResolvePermissionsResponse>(cacheKey, cancellationToken);
        if (cached != null)
        {
            return cached with { FromCache = true };
        }

        // T091: Get active bindings (filtering expired ones)
        var bindings = await _bindingRepository.GetByPrincipalAsync(request.PrincipalId, cancellationToken);

        // T087: Resolve global roles
        var globalBindings = bindings.Where(b => string.IsNullOrEmpty(b.ResourcePath)).ToList();

        // T088: Resolve resource-scoped roles (match against resource path if provided)
        var scopedBindings = bindings.Where(b =>
            !string.IsNullOrEmpty(b.ResourcePath) &&
            MatchesResourcePath(b.ResourcePath, request.ResourcePath))
            .ToList();

        // Combine all matching bindings
        var matchingBindings = globalBindings.Concat(scopedBindings).ToList();

        // Extract role IDs
        var roleIds = matchingBindings.Select(b => b.RoleId).Distinct().ToList();

        // T090: Union of permissions from all matching roles
        var allPermissions = new HashSet<string>();

        foreach (var binding in matchingBindings)
        {
            if (binding.Role?.RolePermissions != null)
            {
                foreach (var rp in binding.Role.RolePermissions)
                {
                    allPermissions.Add(rp.PermissionId);
                }
            }
        }

        var response = new ResolvePermissionsResponse
        {
            PrincipalId = request.PrincipalId,
            Permissions = allPermissions.ToList(),
            Roles = roleIds,
            ResourcePath = request.ResourcePath,
            CacheUntil = DateTime.UtcNow.AddMinutes(CacheTtlMinutes),
            FromCache = false
        };

        // Cache the full response
        await _cacheService.SetAsync(cacheKey, response, TimeSpan.FromMinutes(CacheTtlMinutes), cancellationToken);

        return response;
    }

    /// <inheritdoc />
    public async Task<CheckPermissionResponse> CheckPermissionAsync(CheckPermissionRequest request, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();

        var resolveRequest = new ResolvePermissionsRequest
        {
            PrincipalId = request.PrincipalId,
            ResourcePath = request.ResourcePath
        };

        var resolved = await ResolvePermissionsAsync(resolveRequest, cancellationToken);
        var allowed = resolved.Permissions.Contains(request.PermissionId);

        sw.Stop();

        return new CheckPermissionResponse
        {
            PrincipalId = request.PrincipalId,
            PermissionId = request.PermissionId,
            Allowed = allowed,
            ResourcePath = request.ResourcePath,
            FromCache = resolved.FromCache,
            LatencyMs = sw.ElapsedMilliseconds
        };
    }

    /// <summary>
    /// Matches a binding's resource path against a requested resource path.
    /// Supports hierarchical paths with wildcards (single-level /* and multi-level /**).
    /// </summary>
    /// <param name="bindingPath">Resource path from binding (e.g., "projects/123" or "projects/123/**")</param>
    /// <param name="requestPath">Requested hierarchical path (e.g., "projects/123/datasets/456")</param>
    /// <returns>True if the binding matches the request</returns>
    private bool MatchesResourcePath(string? bindingPath, string? requestPath)
    {
        // If no resource path requested, only global bindings match (which have null bindingPath)
        if (string.IsNullOrEmpty(requestPath))
            return string.IsNullOrEmpty(bindingPath);

        // If binding has no path, it doesn't match resource-scoped requests
        if (string.IsNullOrEmpty(bindingPath))
            return false;

        // Exact match
        if (bindingPath == requestPath)
            return true;

        // Multi-level wildcard: projects/123/** matches all descendants
        if (bindingPath.EndsWith("/**"))
        {
            var prefix = bindingPath[..^3]; // Remove /**
            return requestPath.StartsWith(prefix + "/") || requestPath == prefix;
        }

        // Single-level wildcard: projects/123/* matches projects/123/datasets but NOT projects/123/datasets/456
        if (bindingPath.EndsWith("/*"))
        {
            var prefix = bindingPath[..^2]; // Remove /*
            if (requestPath.StartsWith(prefix + "/"))
            {
                var remainder = requestPath[(prefix.Length + 1)..];
                return !remainder.Contains('/'); // Only one level deep
            }
        }

        return false;
    }

    /// <summary>
    /// Generates a cache key for storing resolved permissions.
    /// Format: "iam:principal:{principalId}:permissions" for global permissions,
    /// "iam:principal:{principalId}:permissions:path:{resourcePath}" for resource-scoped.
    /// Example: "iam:principal:123:permissions:path:projects:456:datasets:789"
    /// </summary>
    /// <param name="principalId">The principal ID.</param>
    /// <param name="resourcePath">Optional hierarchical resource path for scoping.</param>
    /// <returns>Redis cache key string.</returns>
    private string GetCacheKey(Guid principalId, string? resourcePath)
    {
        var key = $"iam:principal:{principalId}:permissions";
        if (!string.IsNullOrEmpty(resourcePath))
        {
            // Sanitize resource path for cache key (replace / with :)
            var sanitizedPath = resourcePath.Replace("/", ":");
            key += $":path:{sanitizedPath}";
        }
        return key;
    }
}
