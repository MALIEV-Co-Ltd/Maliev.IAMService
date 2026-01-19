using Asp.Versioning;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Maliev.IAMService.Api.Authorization;
using Maliev.IAMService.Api.Models.Requests;
using Maliev.IAMService.Api.Services;
using Microsoft.AspNetCore.Mvc;

namespace Maliev.IAMService.Api.Controllers;

/// <summary>
/// Controller for registering and retrieving permissions.
/// Permissions define granular access rights that can be assigned to roles.
/// This controller manages the permission catalog across different services.
/// </summary>
[ApiController]
[ApiVersion("1.0")]
[Route("iam/v{version:apiVersion}/permissions")]
public class PermissionsController : ControllerBase
{
    private readonly IPermissionService _permissionService;
    private readonly ILogger<PermissionsController> _logger;

    /// <summary>
    /// Initializes a new instance of the PermissionsController class.
    /// </summary>
    /// <param name="permissionService">Service for managing permissions and their registrations.</param>
    /// <param name="logger">Logger instance for recording diagnostic information.</param>
    public PermissionsController(IPermissionService permissionService, ILogger<PermissionsController> logger)
    {
        _permissionService = permissionService;
        _logger = logger;
    }

    /// <summary>
    /// Registers new permissions for a service.
    /// </summary>
    /// <remarks>
    /// This endpoint is used by microservices during their startup phase to declare the granular permissions they define.
    /// Permissions must follow the `{service}.{resource}.{action}` format.
    ///
    /// **Security:** This endpoint requires authorization to ensure only Maliev services can register permissions.
    /// </remarks>
    /// <param name="request">Permission registration request containing service name and permission definitions.</param>
    /// <param name="cancellationToken">Cancellation token for the asynchronous operation.</param>
    /// <returns>Registered permissions with their assigned identifiers.</returns>
    /// <response code="200">Returns the full list of permissions registered for this service.</response>
    /// <response code="400">If the permission format is invalid or service name mismatch occurs.</response>
    /// <response code="409">If a permission with the same ID already exists.</response>
    [HttpPost("register")]
    [RequirePermission(IAMPermissions.PermissionsCreate)]
    public async Task<IActionResult> RegisterPermissions([FromBody] RegisterPermissionsRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var permissions = await _permissionService.RegisterPermissionsAsync(request, cancellationToken);
            return Ok(permissions);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return Conflict(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Retrieves permissions with optional filtering by service name.
    /// </summary>
    /// <remarks>
    /// Used by administrators or system explorers to view the available permissions in the platform.
    /// When `serviceName` is provided, only permissions owned by that service are returned.
    /// </remarks>
    /// <param name="serviceName">Optional filter to retrieve permissions for a specific service. If null or empty, returns all permissions.</param>
    /// <param name="cancellationToken">Cancellation token for the asynchronous operation.</param>
    /// <returns>List of permissions, optionally filtered by service.</returns>
    /// <response code="200">Returns the requested permissions.</response>
    /// <response code="401">If the user is not authenticated.</response>
    /// <response code="403">If the user lacks `iam.permissions.list` permission.</response>
    [HttpGet]
    [RequirePermission(IAMPermissions.PermissionsList)]
    public async Task<IActionResult> GetPermissions([FromQuery] string? serviceName, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(serviceName))
        {
            var permissions = await _permissionService.GetByServiceAsync(serviceName, cancellationToken);
            return Ok(permissions);
        }

        var allPermissions = await _permissionService.GetAllAsync(cancellationToken);
        return Ok(allPermissions);
    }

    /// <summary>
    /// Retrieves a single permission by its unique identifier.
    /// </summary>
    /// <remarks>
    /// Returns detailed metadata about a specific permission identifier.
    /// </remarks>
    /// <param name="permissionId">The unique permission identifier to retrieve (e.g., "auth.users.read").</param>
    /// <param name="cancellationToken">Cancellation token for the asynchronous operation.</param>
    /// <returns>The requested permission.</returns>
    /// <response code="200">Returns the requested permission details.</response>
    /// <response code="401">If the user is not authenticated.</response>
    /// <response code="403">If the user lacks `iam.permissions.read` permission.</response>
    /// <response code="404">If the permission identifier is not found.</response>
    [HttpGet("{permissionId}")]
    [RequirePermission(IAMPermissions.PermissionsRead)]
    public async Task<IActionResult> GetPermissionById(string permissionId, CancellationToken cancellationToken)
    {
        var permission = await _permissionService.GetByIdAsync(permissionId, cancellationToken);
        if (permission == null)
        {
            return NotFound(new { error = $"Permission {permissionId} not found" });
        }
        return Ok(permission);
    }
}
