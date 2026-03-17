using Asp.Versioning;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Maliev.IAMService.Domain.Constants;
using Maliev.IAMService.Application.DTOs.Requests;
using Maliev.IAMService.Application.Services;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Maliev.IAMService.Api.Controllers;

/// <summary>
/// Controller for managing role-to-principal bindings.
/// Bindings represent the assignment of roles to principals, granting them the associated permissions.
/// Supports granting, revoking, and querying role assignments with audit trail support.
/// </summary>
[ApiController]
[ApiVersion("1")]
[Route("iam/v{version:apiVersion}/principals/{principalId}/roles")]
public class BindingsController : ControllerBase
{
    private readonly IBindingService _bindingService;
    private readonly ILogger<BindingsController> _logger;

    /// <summary>
    /// Initializes a new instance of the BindingsController class.
    /// </summary>
    /// <param name="bindingService">Service for managing role-to-principal bindings.</param>
    /// <param name="logger">Logger instance for recording diagnostic information.</param>
    public BindingsController(IBindingService bindingService, ILogger<BindingsController> logger)
    {
        _bindingService = bindingService;
        _logger = logger;
    }

    /// <summary>
    /// Grants a role to a principal.
    /// </summary>
    /// <remarks>
    /// Assigns a role (and all its permissions) to a user or service account.
    /// Supports Development Bootstrap: allows access if system has 1 or fewer users.
    /// </remarks>
    /// <param name="principalId">The unique identifier of the principal.</param>
    /// <param name="request">Grant role request.</param>
    /// <param name="cancellationToken">Cancellation token for the asynchronous operation.</param>
    /// <returns>Created binding details.</returns>
    /// <response code="200">If the role was successfully granted.</response>
    /// <response code="403">If the user lacks permission and system is already bootstrapped.</response>
    /// <response code="409">If the principal already has this role or the role doesn't exist.</response>
    [HttpPost]
    public async Task<IActionResult> GrantRole(Guid principalId, [FromBody] GrantRoleRequest request, CancellationToken cancellationToken)
    {
        // 1. Development Bootstrap: Check if we should allow access regardless of permissions
        var principalService = HttpContext.RequestServices.GetRequiredService<IPrincipalService>();
        var principals = await principalService.GetPrincipalsAsync(cancellationToken);

        if (principals.Count() > 1)
        {
            // 2. Standard Path: Check for iam.bindings.create permission
            var authorizationService = HttpContext.RequestServices.GetRequiredService<Microsoft.AspNetCore.Authorization.IAuthorizationService>();
            var authResult = await authorizationService.AuthorizeAsync(User, null, "Permission:" + IAMPermissions.BindingsCreate);

            if (!authResult.Succeeded)
            {
                return Forbid();
            }
        }

        try
        {
            // Get performedBy from authenticated user context
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("sub")?.Value;
            var performedBy = userIdClaim != null ? Guid.Parse(userIdClaim) : Guid.Empty;

            var binding = await _bindingService.GrantRoleAsync(principalId, request, performedBy, cancellationToken);
            return Ok(binding);
        }
        catch (InvalidOperationException ex)
        {
            return Conflict(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Revokes a role from a principal.
    /// </summary>
    /// <remarks>
    /// Removes a specific role assignment. The `bindingId` is the unique ID of the assignment, not the role itself.
    /// Supports Development Bootstrap: allows access if system has 1 or fewer users.
    /// </remarks>
    /// <param name="principalId">The unique identifier of the principal.</param>
    /// <param name="bindingId">The unique identifier of the binding to revoke.</param>
    /// <param name="cancellationToken">Cancellation token for the asynchronous operation.</param>
    /// <returns>No content on success.</returns>
    /// <response code="204">If successfully revoked.</response>
    /// <response code="403">If the user lacks permission and system is already bootstrapped.</response>
    /// <response code="404">If the binding does not exist.</response>
    [HttpDelete("{bindingId}")]
    public async Task<IActionResult> RevokeRole(Guid principalId, Guid bindingId, CancellationToken cancellationToken)
    {
        // 1. Development Bootstrap: Check if we should allow access regardless of permissions
        var principalService = HttpContext.RequestServices.GetRequiredService<IPrincipalService>();
        var principals = await principalService.GetPrincipalsAsync(cancellationToken);

        if (principals.Count() > 1)
        {
            // 2. Standard Path: Check for iam.bindings.delete permission
            var authorizationService = HttpContext.RequestServices.GetRequiredService<Microsoft.AspNetCore.Authorization.IAuthorizationService>();
            var authResult = await authorizationService.AuthorizeAsync(User, null, "Permission:" + IAMPermissions.BindingsDelete);

            if (!authResult.Succeeded)
            {
                return Forbid();
            }
        }

        try
        {
            // Get performedBy from authenticated user context
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("sub")?.Value;
            var performedBy = userIdClaim != null ? Guid.Parse(userIdClaim) : Guid.Empty;

            await _bindingService.RevokeRoleAsync(principalId, bindingId, performedBy, cancellationToken);
            return NoContent();
        }
        catch (InvalidOperationException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Retrieves all role bindings for a specific principal.
    /// </summary>
    /// <remarks>
    /// Lists all roles currently assigned to the user or service account.
    /// Supports Development Bootstrap: allows access if system has 1 or fewer users.
    /// </remarks>
    /// <param name="principalId">The unique identifier of the principal.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of active bindings.</returns>
    /// <response code="200">Returns the list of bindings.</response>
    /// <response code="403">If the user lacks permission and system is already bootstrapped.</response>
    [HttpGet]
    public async Task<IActionResult> GetBindings(Guid principalId, CancellationToken cancellationToken)
    {
        // 1. Development Bootstrap: Check if we should allow access regardless of permissions
        var principalService = HttpContext.RequestServices.GetRequiredService<IPrincipalService>();
        var principals = await principalService.GetPrincipalsAsync(cancellationToken);

        if (principals.Count() > 1)
        {
            // 2. Standard Path: Check for iam.bindings.list permission
            var authorizationService = HttpContext.RequestServices.GetRequiredService<Microsoft.AspNetCore.Authorization.IAuthorizationService>();
            var authResult = await authorizationService.AuthorizeAsync(User, null, "Permission:" + IAMPermissions.BindingsList);

            if (!authResult.Succeeded)
            {
                return Forbid();
            }
        }

        var bindings = await _bindingService.GetBindingsAsync(principalId, cancellationToken);
        return Ok(bindings);
    }

}
