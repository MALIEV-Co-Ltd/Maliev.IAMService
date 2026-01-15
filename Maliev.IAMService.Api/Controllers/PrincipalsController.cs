using Microsoft.AspNetCore.Mvc;
using Asp.Versioning;
using Maliev.IAMService.Api.Services;
using Maliev.IAMService.Api.Models.Requests;
using Maliev.IAMService.Api.Models.Responses;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Maliev.IAMService.Api.Authorization;

namespace Maliev.IAMService.Api.Controllers;

/// <summary>
/// Controller for managing principals (users and service accounts).
/// Provides endpoints for listing and retrieving detailed information about platform identities.
/// </summary>
[ApiController]
[ApiVersion("1.0")]
[Route("iam/v{version:apiVersion}/principals")]
public class PrincipalsController : ControllerBase
{
    private readonly IPrincipalService _principalService;
    private readonly ILogger<PrincipalsController> _logger;

    /// <summary>
    /// Initializes a new instance of the PrincipalsController class.
    /// </summary>
    /// <param name="principalService">Service for managing principals.</param>
    /// <param name="logger">Logger instance.</param>
    public PrincipalsController(IPrincipalService principalService, ILogger<PrincipalsController> logger)
    {
        _principalService = principalService;
        _logger = logger;
    }

    /// <summary>
    /// Lists all principals in the system.
    /// </summary>
    /// <remarks>
    /// Returns a comprehensive list of all users and service accounts registered in the IAM service.
    /// </remarks>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of principals.</returns>
    /// <response code="200">The requested list.</response>
    /// <response code="403">If the user lacks `iam.principals.list` permission.</response>
    [HttpGet]
    [RequirePermission(IAMPermissions.PrincipalsList)]
    public async Task<IActionResult> GetPrincipals(CancellationToken cancellationToken)
    {
        var principals = await _principalService.GetPrincipalsAsync(cancellationToken);
        return Ok(principals);
    }

    /// <summary>
    /// Retrieves a single principal by its unique identifier.
    /// </summary>
    /// <param name="id">The unique identifier of the principal.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Principal details.</returns>
    /// <response code="200">If found.</response>
    /// <response code="403">If the user lacks `iam.principals.read` permission.</response>
    /// <response code="404">If the principal does not exist.</response>
    [HttpGet("{id}")]
    [RequirePermission(IAMPermissions.PrincipalsRead)]
    public async Task<IActionResult> GetPrincipalById(Guid id, CancellationToken cancellationToken)
    {
        var principal = await _principalService.GetByIdAsync(id, cancellationToken);
        if (principal == null)
        {
            return NotFound(new { error = $"Principal {id} not found" });
        }

        var response = new PrincipalResponse
        {
            PrincipalId = principal.PrincipalId,
            PrincipalType = principal.PrincipalType,
            Email = principal.Email,
            DisplayName = principal.DisplayName,
            LinkedService = principal.LinkedService,
            LinkedEntityId = principal.LinkedEntityId,
            IsActive = principal.IsActive,
            CreatedAt = principal.CreatedAt,
            UpdatedAt = principal.UpdatedAt
        };

        return Ok(response);
    }

    /// <summary>
    /// Deletes a principal and all its associated bindings.
    /// </summary>
    /// <param name="id">The unique identifier of the principal to delete.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>No content on success.</returns>
    /// <response code="204">If successfully deleted.</response>
    /// <response code="403">If the user lacks `iam.principals.delete` permission.</response>
    /// <response code="404">If the principal does not exist.</response>
    [HttpDelete("{id}")]
    [RequirePermission(IAMPermissions.PrincipalsDelete)]
    public async Task<IActionResult> DeletePrincipal(Guid id, CancellationToken cancellationToken)
    {
        try
        {
            await _principalService.DeleteAsync(id, cancellationToken);
            return NoContent();
        }
        catch (InvalidOperationException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }
}
