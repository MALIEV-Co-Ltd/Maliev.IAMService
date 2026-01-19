using Asp.Versioning;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Maliev.IAMService.Api.Authorization;
using Maliev.IAMService.Api.Models.Requests;
using Maliev.IAMService.Api.Models.Responses;
using Maliev.IAMService.Api.Services;
using Microsoft.AspNetCore.Mvc;

namespace Maliev.IAMService.Api.Controllers;

/// <summary>
/// Controller for managing service accounts and their API keys.
/// </summary>
[ApiController]
[ApiVersion("1.0")]
[Route("iam/v{version:apiVersion}/service-accounts")]
public class ServiceAccountsController : ControllerBase
{
    private readonly IPrincipalService _principalService;
    private readonly ILogger<ServiceAccountsController> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="ServiceAccountsController"/> class.
    /// </summary>
    /// <param name="principalService">The principal service.</param>
    /// <param name="logger">The logger.</param>
    public ServiceAccountsController(IPrincipalService principalService, ILogger<ServiceAccountsController> logger)
    {
        _principalService = principalService;
        _logger = logger;
    }

    /// <summary>
    /// Creates a new service account.
    /// </summary>
    /// <param name="request">The create request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The created service account details.</returns>
    [HttpPost]
    [RequirePermission(IAMPermissions.PrincipalsCreate)]
    public async Task<IActionResult> CreateServiceAccount([FromBody] CreateServiceAccountRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var response = await _principalService.CreateServiceAccountAsync(request, cancellationToken);
            return CreatedAtAction(nameof(GetServiceAccounts), response);
        }
        catch (InvalidOperationException ex)
        {
            return Conflict(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Lists all service accounts.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A list of service accounts.</returns>
    [HttpGet]
    [RequirePermission(IAMPermissions.PrincipalsList)]
    public async Task<IActionResult> GetServiceAccounts(CancellationToken cancellationToken)
    {
        var accounts = await _principalService.GetServiceAccountsAsync(cancellationToken);
        return Ok(accounts);
    }

    /// <summary>
    /// Rotates the API key for a service account.
    /// </summary>
    /// <param name="principalId">The principal identifier.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The new API key.</returns>
    [HttpPost("{principalId:guid}/rotate-key")]
    [RequirePermission(IAMPermissions.PrincipalsUpdate)]
    public async Task<IActionResult> RotateApiKey(Guid principalId, CancellationToken cancellationToken)
    {
        try
        {
            var response = await _principalService.RotateApiKeyAsync(principalId, cancellationToken);
            return Ok(response);
        }
        catch (InvalidOperationException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Gets the effective permissions for a principal.
    /// </summary>
    /// <param name="principalId">The principal identifier.</param>
    /// <param name="resourceType">Optional resource type.</param>
    /// <param name="resourceId">Optional resource identifier.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The effective permissions.</returns>
    [HttpGet("{principalId:guid}/effective-permissions")]
    [RequirePermission(IAMPermissions.AuthResolvePermissions)]
    public async Task<IActionResult> GetEffectivePermissions(
        Guid principalId,
        [FromQuery] string? resourceType,
        [FromQuery] string? resourceId,
        CancellationToken cancellationToken)
    {
        string? resourcePath = null;
        if (!string.IsNullOrEmpty(resourceType) && !string.IsNullOrEmpty(resourceId))
        {
            resourcePath = $"{resourceType}/{resourceId}";
        }

        try
        {
            var response = await _principalService.GetEffectivePermissionsAsync(principalId, resourcePath, cancellationToken);
            return Ok(response);
        }
        catch (InvalidOperationException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }
}
