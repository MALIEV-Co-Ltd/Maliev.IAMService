using Microsoft.AspNetCore.Mvc;
using Asp.Versioning;
using Maliev.IAMService.Api.Services;
using Maliev.IAMService.Api.Models.Requests;
using Maliev.IAMService.Api.Models.Responses;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Maliev.IAMService.Api.Authorization;

namespace Maliev.IAMService.Api.Controllers;

/// <summary>
/// Controller for managing service accounts and their API keys.
/// Handles creation, rotation, and querying of service account principals including their effective permissions.
/// </summary>
[ApiController]
[ApiVersion("1.0")]
[Route("iam/v{version:apiVersion}/service-accounts")]
public class PrincipalsController : ControllerBase
{
    private readonly IPrincipalService _principalService;
    private readonly IPermissionResolver _permissionResolver;
    private readonly ILogger<PrincipalsController> _logger;

    /// <summary>
    /// Initializes a new instance of the PrincipalsController class.
    /// </summary>
    /// <param name="principalService">Service for managing service account principals.</param>
    /// <param name="permissionResolver">Service for resolving and validating permissions.</param>
    /// <param name="logger">Logger instance for recording diagnostic information.</param>
    public PrincipalsController(
        IPrincipalService principalService,
        IPermissionResolver permissionResolver,
        ILogger<PrincipalsController> logger)
    {
        _principalService = principalService;
        _permissionResolver = permissionResolver;
        _logger = logger;
    }

    /// <summary>
    /// Creates a new user principal linked to an external service.
    /// </summary>
    /// <remarks>
    /// Links an identity in IAM to a record in another service (e.g., an Employee in EmployeeService).
    /// Once linked, roles can be assigned to this principal to control their platform access.
    /// </remarks>
    /// <param name="request">User principal creation request.</param>
    /// <param name="cancellationToken">Cancellation token for the asynchronous operation.</param>
    /// <returns>Created user principal ID.</returns>
    /// <response code="201">If the principal was successfully created.</response>
    /// <response code="403">If the user lacks `iam.principals.create` permission.</response>
    /// <response code="409">If a principal with the same email or link already exists.</response>
    [HttpPost("users")]
    [RequirePermission(IAMPermissions.PrincipalsCreate)]
    public async Task<IActionResult> CreateUserPrincipal([FromBody] CreateUserPrincipalRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var principal = await _principalService.CreateAsync(
                principalType: "user",
                email: request.Email,
                linkedService: request.LinkedService,
                linkedEntityId: request.LinkedEntityId,
                cancellationToken: cancellationToken);

            return StatusCode(201, new { PrincipalId = principal.PrincipalId });
        }
        catch (InvalidOperationException ex)
        {
            return Conflict(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Creates a new service account with an API key.
    /// </summary>
    /// <remarks>
    /// Service accounts are used for machine-to-machine communication. 
    /// **Important:** The generated API key is returned ONLY ONCE in the response. It cannot be retrieved later.
    /// </remarks>
    /// <param name="request">Service account creation request.</param>
    /// <param name="cancellationToken">Cancellation token for the asynchronous operation.</param>
    /// <returns>Service account details and API key.</returns>
    /// <response code="201">If created successfully.</response>
    /// <response code="403">If the user lacks `iam.principals.create` permission.</response>
    // T124: Create service account
    [HttpPost]
    [RequirePermission(IAMPermissions.PrincipalsCreate)]
    public async Task<IActionResult> CreateServiceAccount([FromBody] CreateServiceAccountRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var serviceAccount = await _principalService.CreateServiceAccountAsync(request, cancellationToken);
            return StatusCode(201, serviceAccount);
        }
        catch (InvalidOperationException ex)
        {
            return Conflict(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Rotates the API key for a service account.
    /// </summary>
    /// <remarks>
    /// Generates a new API key and invalidates the previous one immediately.
    /// </remarks>
    /// <param name="id">The unique identifier of the service account.</param>
    /// <param name="cancellationToken">Cancellation token for the asynchronous operation.</param>
    /// <returns>New API key details.</returns>
    /// <response code="200">If rotated successfully.</response>
    /// <response code="403">If the user lacks `iam.principals.update` permission.</response>
    /// <response code="404">If the service account does not exist.</response>
    // T125: Rotate API key
    [HttpPost("{id}/rotate-key")]
    [RequirePermission(IAMPermissions.PrincipalsUpdate)]
    public async Task<IActionResult> RotateApiKey(Guid id, CancellationToken cancellationToken)
    {
        try
        {
            var result = await _principalService.RotateApiKeyAsync(id, cancellationToken);
            return Ok(result);
        }
        catch (InvalidOperationException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Lists all service accounts.
    /// </summary>
    /// <remarks>
    /// Returns basic metadata about service accounts. Does not expose API keys.
    /// </remarks>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of service accounts.</returns>
    /// <response code="200">The requested list.</response>
    /// <response code="403">If the user lacks `iam.principals.list` permission.</response>
    // T126: List service accounts
    [HttpGet]
    [RequirePermission(IAMPermissions.PrincipalsList)]
    public async Task<IActionResult> GetServiceAccounts(CancellationToken cancellationToken)
    {
        var serviceAccounts = await _principalService.GetServiceAccountsAsync(cancellationToken);
        return Ok(serviceAccounts);
    }

    /// <summary>
    /// Queries effective permissions for a principal.
    /// </summary>
    /// <remarks>
    /// Computes the union of all permissions from all roles assigned to the principal.
    /// Optional `resourcePath` allows checking permissions for a specific object (e.g., `projects/123`).
    /// </remarks>
    /// <param name="id">The unique identifier of the principal.</param>
    /// <param name="resourcePath">Optional hierarchical resource path filter.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Effective permissions list.</returns>
    /// <response code="200">The resolved permissions.</response>
    /// <response code="403">If the user lacks `iam.principals.read` permission.</response>
    /// <response code="404">If the principal does not exist.</response>
    // T150: Query effective permissions for a principal
    [HttpGet("{id}/effective-permissions")]
    [RequirePermission(IAMPermissions.PrincipalsRead)]
    public async Task<IActionResult> GetEffectivePermissions(
        Guid id,
        [FromQuery] string? resourcePath = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await _principalService.GetEffectivePermissionsAsync(
                id, resourcePath, cancellationToken);
            return Ok(response);
        }
        catch (InvalidOperationException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }
}
