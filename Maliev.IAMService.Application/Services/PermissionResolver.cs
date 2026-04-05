using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.DTOs.Responses;
using Maliev.IAMService.Application.Interfaces;
using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace Maliev.IAMService.Application.Services;

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
    /// <param name="request">Permission resolution request containing principal ID and optional resource scope.</param>
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
/// Uses a 5-minute cache TTL and supports hierarchical resource path matching.
/// </summary>
public class PermissionResolver : IPermissionResolver
{
    private readonly IBindingRepository _bindingRepository;
    private readonly IPrincipalService _principalService;
    private readonly ICacheService _cacheService;
    private readonly ILogger<PermissionResolver> _logger;
    private const int CacheTtlMinutes = 5;

    /// <summary>
    /// Initializes a new instance of the <see cref="PermissionResolver"/> class.
    /// </summary>
    /// <param name="bindingRepository">The binding repository.</param>
    /// <param name="principalService">The principal service.</param>
    /// <param name="cacheService">The cache service.</param>
    /// <param name="logger">The logger.</param>
    public PermissionResolver(
        IBindingRepository bindingRepository,
        IPrincipalService principalService,
        ICacheService cacheService,
        ILogger<PermissionResolver> logger)
    {
        _bindingRepository = bindingRepository;
        _principalService = principalService;
        _cacheService = cacheService;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<ResolvePermissionsResponse> ResolvePermissionsAsync(ResolvePermissionsRequest request, CancellationToken cancellationToken = default)
    {
        Guid principalGuid;
        try
        {
            principalGuid = await _principalService.ResolvePrincipalIdAsync(request.PrincipalId, cancellationToken);
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "Failed to resolve principal {PrincipalId}", request.PrincipalId);
            return new ResolvePermissionsResponse
            {
                PrincipalId = Guid.Empty,
                Permissions = new List<string>(),
                Roles = new List<string>(),
                ResourcePath = request.ResourcePath,
                FromCache = false
            };
        }

        var cacheKey = GetCacheKey(principalGuid, request.ResourcePath);

        var cached = await _cacheService.GetAsync<ResolvePermissionsResponse>(cacheKey, cancellationToken);
        if (cached != null)
        {
            return cached with { FromCache = true };
        }

        var bindings = await _bindingRepository.GetByPrincipalAsync(principalGuid, cancellationToken);

        var globalBindings = bindings.Where(b => string.IsNullOrEmpty(b.ResourcePath) || b.ResourcePath == "*").ToList();

        var scopedBindings = bindings.Where(b =>
            !string.IsNullOrEmpty(b.ResourcePath) &&
            MatchesResourcePath(b.ResourcePath, request.ResourcePath))
            .ToList();

        var matchingBindings = globalBindings.Concat(scopedBindings).ToList();

        var roleIds = matchingBindings.Select(b => b.RoleId).Distinct().ToList();

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

        var directBindings = await _bindingRepository.GetDirectPermissionsByPrincipalAsync(principalGuid, cancellationToken);
        foreach (var db in directBindings)
        {
            if (string.IsNullOrEmpty(db.ResourcePath) || MatchesResourcePath(db.ResourcePath, request.ResourcePath))
            {
                allPermissions.Add(db.PermissionId);
            }
        }

        var response = new ResolvePermissionsResponse
        {
            PrincipalId = principalGuid,
            Permissions = allPermissions.ToList(),
            Roles = roleIds,
            ResourcePath = request.ResourcePath,
            CacheUntil = DateTime.UtcNow.AddMinutes(CacheTtlMinutes),
            FromCache = false
        };

        // ⚠ BOOTSTRAP SAFETY — do NOT cache empty permission responses.
        //
        // During first-login, AuthService polls ResolvePermissions every 500 ms for up to 10 s while
        // the EmployeeCreatedConsumer provisions the Platform Owner role asynchronously over RabbitMQ.
        //
        // If an empty result ({Roles:[], Permissions:[]}) is cached here, every subsequent poll in that
        // 10 s window becomes a cache hit that still returns zero permissions — even after the consumer
        // commits the PrincipalRoleBinding and calls CacheService.RemoveAsync.  The cache clear races
        // against the cache write; on a fresh DB the consumer typically wins only AFTER the polling
        // window has already closed, so the user receives a JWT with no permissions and gets 403s
        // on every downstream API call.
        //
        // Empty results are a transient state (bootstrap hasn't finished) and are cheap to re-query.
        // Only cache once at least one role or permission is confirmed to exist.
        if (roleIds.Count > 0 || allPermissions.Count > 0)
        {
            await _cacheService.SetAsync(cacheKey, response, TimeSpan.FromMinutes(CacheTtlMinutes), cancellationToken);
        }

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

        var allowed = resolved.Roles.Any(r => string.Equals(r, "roles.platform.owner", StringComparison.OrdinalIgnoreCase)) ||
                      resolved.Permissions.Contains("*") ||
                      resolved.Permissions.Contains(request.PermissionId);

        if (!allowed)
        {
            _logger.LogWarning("Permission denied for Principal {PrincipalId}: {Permission}. Resolved Roles: {Roles}, Permissions Count: {Count}",
                request.PrincipalId, request.PermissionId, string.Join(",", resolved.Roles), resolved.Permissions.Count);
        }

        sw.Stop();

        return new CheckPermissionResponse
        {
            PrincipalId = resolved.PrincipalId,
            PermissionId = request.PermissionId,
            Allowed = allowed,
            ResourcePath = request.ResourcePath,
            FromCache = resolved.FromCache,
            LatencyMs = sw.ElapsedMilliseconds
        };
    }

    /// <summary>
    /// Matches a binding's resource path against a requested resource path.
    /// Supports hierarchical paths (inheritance) and wildcards (single-level /* and multi-level /**).
    /// </summary>
    /// <param name="bindingPath">Resource path from binding.</param>
    /// <param name="requestPath">Requested hierarchical path.</param>
    /// <returns>True if the binding matches the request.</returns>
    private bool MatchesResourcePath(string? bindingPath, string? requestPath)
    {
        if (string.IsNullOrEmpty(requestPath))
            return string.IsNullOrEmpty(bindingPath) || bindingPath == "*";

        if (string.IsNullOrEmpty(bindingPath))
            return false;

        if (bindingPath == "*")
            return true;

        if (requestPath == bindingPath || requestPath.StartsWith(bindingPath + "/"))
            return true;

        if (bindingPath.EndsWith("/**"))
        {
            var prefix = bindingPath[..^3];
            return requestPath.StartsWith(prefix + "/") || requestPath == prefix;
        }

        if (bindingPath.EndsWith("/*"))
        {
            var prefix = bindingPath[..^2];
            if (requestPath.StartsWith(prefix + "/"))
            {
                var remainder = requestPath[(prefix.Length + 1)..];
                return !remainder.Contains('/');
            }
        }

        return false;
    }

    /// <summary>
    /// Generates a cache key for storing resolved permissions.
    /// </summary>
    /// <param name="principalId">The principal ID.</param>
    /// <param name="resourcePath">Optional hierarchical resource path for scoping.</param>
    /// <returns>Redis cache key string.</returns>
    private string GetCacheKey(Guid principalId, string? resourcePath)
    {
        var key = $"iam:principal:{principalId}:permissions";
        if (!string.IsNullOrEmpty(resourcePath))
        {
            var hashBytes = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(resourcePath.ToLowerInvariant()));
            var hash = Convert.ToHexString(hashBytes).ToLowerInvariant();
            key += $":path:{hash}";
        }
        return key;
    }
}
