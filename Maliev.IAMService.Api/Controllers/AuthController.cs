using System.Globalization;
using Asp.Versioning;
using Maliev.Aspire.ServiceDefaults;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Maliev.IAMService.Api.Authorization;
using Maliev.IAMService.Domain.Constants;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Maliev.IAMService.Api.Controllers;

/// <summary>
/// Controller for authentication and authorization operations including permission checks and JWT token management.
/// </summary>
[ApiController]
[ApiVersion("1")]
[Route("iam/v{version:apiVersion}/auth")]
public class AuthController : ControllerBase
{
    private readonly IPermissionResolver _permissionResolver;
    private readonly ITokenService _tokenService;
    private readonly ILogger<AuthController> _logger;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly LivePermissionCheckGuard _livePermissionCheckGuard;

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthController"/> class.
    /// </summary>
    /// <param name="permissionResolver">Service for resolving and checking permissions.</param>
    /// <param name="tokenService">Service for JWT token operations.</param>
    /// <param name="logger">Logger instance.</param>
    /// <param name="scopeFactory">Service scope factory for creating fresh DbContext instances.</param>
    /// <param name="livePermissionCheckGuard">Guard for authoritative permission-check access and capacity.</param>
    public AuthController(
        IPermissionResolver permissionResolver,
        ITokenService tokenService,
        ILogger<AuthController> logger,
        IServiceScopeFactory scopeFactory,
        LivePermissionCheckGuard livePermissionCheckGuard)
    {
        _permissionResolver = permissionResolver;
        _tokenService = tokenService;
        _logger = logger;
        _scopeFactory = scopeFactory;
        _livePermissionCheckGuard = livePermissionCheckGuard;
    }

    /// <summary>
    /// Resolves all effective permissions for a principal, optionally scoped to a specific resource.
    /// Uses Redis caching with 5-minute TTL for optimal performance (target &lt;10ms).
    /// Requires explicit permission resolution access.
    /// </summary>
    /// <param name="request">The permission resolution request containing principal ID and optional resource scope.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of permissions granted to the principal.</returns>
    [HttpPost("resolve-permissions")]
    [RequirePermission(IAMPermissions.AuthResolvePermissions)]
    public async Task<IActionResult> ResolvePermissions([FromBody] ResolvePermissionsRequest request, CancellationToken cancellationToken)
    {
        // 1. Service Account Bypass: Allow other services to resolve permissions for users
        var userType = User.FindFirst("user_type")?.Value;
        if (userType == "service")
        {
            var response = await _permissionResolver.ResolvePermissionsAsync(request, cancellationToken);
            return Ok(response);
        }

        var res = await _permissionResolver.ResolvePermissionsAsync(request, cancellationToken);
        return Ok(res);
    }

    /// <summary>
    /// Resolves effective permissions for AuthService token issuance using an isolated,
    /// target-bound, short-lived asymmetric capability.
    /// </summary>
    /// <param name="request">The exact principal bound into the capability.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The authoritative permission and role response.</returns>
    [HttpPost("token-issuance/resolve-permissions")]
    [Authorize(Policy = TokenIssuanceCapabilityAuthentication.Policy)]
    public async Task<IActionResult> ResolvePermissionsForTokenIssuance(
        [FromBody] ResolvePermissionsRequest request,
        CancellationToken cancellationToken)
    {
        if (!TokenIssuanceCapabilityAuthentication.IsBoundToTarget(User, request.PrincipalId)
            || request.ResourcePath is not null
            || request.RequestTime.HasValue
            || request.RequestIp is not null)
        {
            return Forbid(TokenIssuanceCapabilityAuthentication.Scheme);
        }

        var response = await _permissionResolver.ResolvePermissionsAsync(request, cancellationToken);
        return Ok(response);
    }

    /// <summary>
    /// Checks if a principal has a specific permission, optionally scoped to a resource.
    /// Includes latency tracking and supports hierarchical resource matching.
    /// Requires explicit permission-check access.
    /// </summary>
    /// <param name="request">The permission check request containing principal ID, permission ID, and optional resource scope.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Boolean result indicating if the permission is granted, along with latency metrics.</returns>
    [HttpPost("check-permission")]
    [RequirePermission(IAMPermissions.AuthCheckPermission)]
    public async Task<IActionResult> CheckPermission([FromBody] CheckPermissionRequest request, CancellationToken cancellationToken)
    {
        IDisposable? liveCheckLease = null;
        if (request.BypassCache)
        {
            var credentialValues = Request.Headers["X-Maliev-IAM-Live-Check-Key"];
            var credential = credentialValues.Count == 1 ? credentialValues[0] : null;
            var admission = await _livePermissionCheckGuard.AcquireAsync(
                User,
                request.PrincipalId,
                credential,
                cancellationToken);
            if (admission.Decision == LivePermissionCheckDecision.Forbidden)
            {
                return CreateProblem(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "Live permission check forbidden",
                    detail: "Authoritative permission checks are restricted to trusted platform services.");
            }

            if (admission.Decision == LivePermissionCheckDecision.RateLimited)
            {
                var retryAfterSeconds = Math.Max(1, (int)Math.Ceiling((admission.RetryAfter ?? TimeSpan.FromSeconds(1)).TotalSeconds));
                Response.Headers.RetryAfter = retryAfterSeconds.ToString(CultureInfo.InvariantCulture);
                return CreateProblem(
                    statusCode: StatusCodes.Status429TooManyRequests,
                    title: "Live permission check capacity exceeded",
                    detail: "Authoritative permission-check capacity is temporarily exhausted. Retry after the indicated delay.");
            }

            liveCheckLease = admission.Lease;
        }

        using (liveCheckLease)
        {
            var res = await _permissionResolver.CheckPermissionAsync(request, cancellationToken);

            _logger.LogInformation("Permission check completed in {LatencyMs}ms for principal {PrincipalId}, permission {PermissionId}, allowed: {Allowed}",
                res.LatencyMs, request.PrincipalId, request.PermissionId, res.Allowed);

            return Ok(res);
        }
    }

    private ObjectResult CreateProblem(int statusCode, string title, string detail)
    {
        var result = Problem(statusCode: statusCode, title: title, detail: detail);
        result.ContentTypes.Add("application/problem+json");
        return result;
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
    [AllowAnonymous]
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
    [AllowAnonymous]
    public async Task<IActionResult> GetJwks(CancellationToken cancellationToken)
    {
        var jwks = await _tokenService.GetJwksAsync(cancellationToken);
        return Content(jwks, "application/json");
    }
}
