using Asp.Versioning;
using Maliev.Aspire.ServiceDefaults;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Maliev.IAMService.Api.Authorization;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Maliev.IAMService.Api.Controllers;

/// <summary>
/// Controller for authentication and authorization operations including permission checks and JWT token management.
/// </summary>
[ApiController]
[ApiVersion("1.0")]
[Route("iam/v{version:apiVersion}/auth")]
public class AuthController : ControllerBase
{
    private readonly IPermissionResolver _permissionResolver;
    private readonly ITokenService _tokenService;
    private readonly ILogger<AuthController> _logger;
    private readonly IServiceScopeFactory _scopeFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthController"/> class.
    /// </summary>
    /// <param name="permissionResolver">Service for resolving and checking permissions.</param>
    /// <param name="tokenService">Service for JWT token operations.</param>
    /// <param name="logger">Logger instance.</param>
    /// <param name="scopeFactory">Service scope factory for creating fresh DbContext instances.</param>
    public AuthController(
        IPermissionResolver permissionResolver,
        ITokenService tokenService,
        ILogger<AuthController> logger,
        IServiceScopeFactory scopeFactory)
    {
        _permissionResolver = permissionResolver;
        _tokenService = tokenService;
        _logger = logger;
        _scopeFactory = scopeFactory;
    }

    /// <summary>
    /// Resolves all effective permissions for a principal, optionally scoped to a specific resource.
    /// Uses Redis caching with 5-minute TTL for optimal performance (target &lt;10ms).
    /// Supports Development Bootstrap and Service Account bypass.
    /// </summary>
    /// <param name="request">The permission resolution request containing principal ID and optional resource scope.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of permissions granted to the principal.</returns>
    [HttpPost("resolve-permissions")]
    public async Task<IActionResult> ResolvePermissions([FromBody] ResolvePermissionsRequest request, CancellationToken cancellationToken)
    {
        // 1. Service Account Bypass: Allow other services to resolve permissions for users
        var userType = User.FindFirst("user_type")?.Value;
        if (userType == "service")
        {
            var response = await _permissionResolver.ResolvePermissionsAsync(request, cancellationToken);
            return Ok(response);
        }

        // 2. Development Bootstrap: Allow access if system has 1 or fewer users
        var principalService = HttpContext.RequestServices.GetRequiredService<IPrincipalService>();
        var principals = await principalService.GetPrincipalsAsync(cancellationToken);

        if (principals.Count() > 1)
        {
            // 3. Standard Path: Check for iam.auth.resolve-permissions permission
            var authorizationService = HttpContext.RequestServices.GetRequiredService<Microsoft.AspNetCore.Authorization.IAuthorizationService>();
            var authResult = await authorizationService.AuthorizeAsync(User, null, "Permission:" + IAMPermissions.AuthResolvePermissions);

            if (!authResult.Succeeded)
            {
                return Forbid();
            }
        }

        var res = await _permissionResolver.ResolvePermissionsAsync(request, cancellationToken);
        return Ok(res);
    }

    /// <summary>
    /// Checks if a principal has a specific permission, optionally scoped to a resource.
    /// Includes latency tracking and supports hierarchical resource matching.
    /// Supports Development Bootstrap and Service Account bypass.
    /// </summary>
    /// <param name="request">The permission check request containing principal ID, permission ID, and optional resource scope.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Boolean result indicating if the permission is granted, along with latency metrics.</returns>
    [HttpPost("check-permission")]
    public async Task<IActionResult> CheckPermission([FromBody] CheckPermissionRequest request, CancellationToken cancellationToken)
    {
        // 1. Service Account Bypass: Allow other services to check permissions for users
        var userType = User.FindFirst("user_type")?.Value;
        if (userType == "service")
        {
            var response = await _permissionResolver.CheckPermissionAsync(request, cancellationToken);
            return Ok(response);
        }

        // 2. Development Bootstrap: Allow access if system has 1 or fewer users
        var principalService = HttpContext.RequestServices.GetRequiredService<IPrincipalService>();
        var principals = await principalService.GetPrincipalsAsync(cancellationToken);

        if (principals.Count() > 1)
        {
            // 3. Standard Path: Check for iam.auth.check-permission permission
            var authorizationService = HttpContext.RequestServices.GetRequiredService<Microsoft.AspNetCore.Authorization.IAuthorizationService>();
            var authResult = await authorizationService.AuthorizeAsync(User, null, "Permission:" + IAMPermissions.AuthCheckPermission);

            if (!authResult.Succeeded)
            {
                return Forbid();
            }
        }

        var res = await _permissionResolver.CheckPermissionAsync(request, cancellationToken);

        _logger.LogInformation("Permission check completed in {LatencyMs}ms for principal {PrincipalId}, permission {PermissionId}, allowed: {Allowed}",
            res.LatencyMs, request.PrincipalId, request.PermissionId, res.Allowed);

        return Ok(res);
    }

    /// <summary>
    /// Checks multiple permissions for a principal in a single request.
    /// More efficient than multiple individual calls for complex authorization scenarios.
    /// </summary>
    /// <param name="request">Bulk check request containing principal ID and list of permission checks.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Dictionary mapping permission IDs to boolean results.</returns>
    [HttpPost("check-permissions")]
    [RequirePermission(IAMPermissions.AuthCheckPermission)]
    public async Task<IActionResult> CheckPermissions([FromBody] BulkCheckPermissionRequest request, CancellationToken cancellationToken)
    {
        var results = new Dictionary<string, bool>();

        foreach (var permCheck in request.PermissionChecks)
        {
            var checkRequest = new CheckPermissionRequest
            {
                PrincipalId = request.PrincipalId,
                PermissionId = permCheck.PermissionId,
                ResourcePath = permCheck.ResourcePath
            };

            var response = await _permissionResolver.CheckPermissionAsync(checkRequest, cancellationToken);
            results[permCheck.PermissionId] = response.Allowed;
        }

        _logger.LogInformation("Bulk permission check completed for principal {PrincipalId}, {Count} checks",
            request.PrincipalId, request.PermissionChecks.Count);

        return Ok(results);
    }

    /// <summary>
    /// Issues a new JWT access token and refresh token for a principal.
    /// Token includes principal ID, permissions, and roles as claims. Uses RS256 signing with 2048-bit RSA keys.
    /// Rate limited to 10 requests per minute.
    /// </summary>
    /// <param name="request">Token issuance request containing principal ID and optional resource scope.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>JWT access token, refresh token, and expiration details.</returns>
    [HttpPost("token")]
    [EnableRateLimiting(RateLimitPolicies.Auth)]
    [RequirePermission(IAMPermissions.AuthIssueToken)]
    public async Task<IActionResult> IssueToken([FromBody] IssueTokenRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var response = await _tokenService.IssueTokenAsync(request, cancellationToken);
            return Ok(response);
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Refreshes an expired access token using a valid refresh token.
    /// Invalidates the old refresh token and issues a new token pair.
    /// Rate limited to 10 requests per minute.
    /// </summary>
    /// <param name="request">Refresh request containing the refresh token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>New JWT access token, new refresh token, and expiration details.</returns>
    [HttpPost("token/refresh")]
    [EnableRateLimiting(RateLimitPolicies.Auth)]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var response = await _tokenService.RefreshTokenAsync(request, cancellationToken);
            return Ok(response);
        }
        catch (InvalidOperationException ex)
        {
            return Unauthorized(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Returns the JSON Web Key Set (JWKS) containing the public keys for JWT signature verification.
    /// Used by other services to verify JWT tokens issued by this IAM service.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>JWKS JSON containing RSA public key information.</returns>
    [HttpGet(".well-known/jwks.json")]
    public async Task<IActionResult> GetJwks(CancellationToken cancellationToken)
    {
        var jwks = await _tokenService.GetJwksAsync(cancellationToken);
        return Content(jwks, "application/json");
    }
}
